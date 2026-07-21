#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
EXAMPLE_DIR = ROOT / "example"
if str(EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(EXAMPLE_DIR))

import grpc

from cri_common import configure_logging, labels_match, log_rpc, logger, normalize_image_ref
import tools.api_pb2 as api_pb2
import tools.api_pb2_grpc as api_pb2_grpc


SOCKET_PATH = "/tmp/pnfroot.sock"
IMAGE_STORE_DIR = "/tmp/pnfroot/images"
IMAGE_PLATFORM = "linux/amd64"
DEFAULT_IMAGE_SIZE = 1
IMAGE_METADATA_FILE = "pnfroot-image.json"


def cri_time_ns() -> str:
    ns = time.time_ns()
    sec = ns // 1_000_000_000
    nsec = ns % 1_000_000_000
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(sec))
    return f"{base}.{nsec:09d}Z"


def pipe_to_cri_log(pipe, log_path: str, stream: str) -> None:
    with open(log_path, "ab", buffering=0) as handle:
        for line in iter(pipe.readline, b""):
            ts = cri_time_ns().encode()
            handle.write(ts + b" " + stream.encode() + b" F " + line)


def pull_image_to_dir(image: str, output: str, platform: str = IMAGE_PLATFORM) -> str:
    """Pull an image into a local directory.

    This implementation is intentionally simple and works with local directories
    already present in the workspace (for example ./ubuntu_c). For real registry
    pulls, this can be extended later.
    """

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)

    aliases = []
    if image:
        aliases.append(image)
        aliases.append(image.split("@", 1)[0].split(":", 1)[0])
        aliases.append(image.rsplit("/", 1)[-1].split("@", 1)[0].split(":", 1)[0])
        aliases.append(image.replace(":", "_"))
        aliases.append(image.split("/", 1)[-1].replace(":", "_"))

    candidates = []
    for alias in aliases:
        if not alias:
            continue
        candidates.extend([
            Path(alias),
            Path.cwd() / alias,
            ROOT / alias,
            EXAMPLE_DIR / alias,
        ])

    for candidate in candidates:
        if not candidate.exists():
            continue
        if candidate.is_dir():
            _copy_tree_safe(candidate, output_path)
            return str(output_path)
        if candidate.is_file():
            shutil.copy2(candidate, output_path / candidate.name)
            return str(output_path)

    fallback_roots = [ROOT / "ubuntu_c", ROOT / "ubuntu_n"]
    for fallback in fallback_roots:
        if fallback.exists():
            _copy_tree_safe(fallback, output_path)
            return str(output_path)

    raise FileNotFoundError(f"cannot resolve image {image!r} from local filesystem")


def _copy_tree_safe(src: Path, dst: Path) -> None:
    for item in src.iterdir():
        target = dst / item.name
        if item.is_symlink():
            target.symlink_to(item.resolve())
            continue
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            _copy_tree_safe(item, target)
        elif item.is_file():
            shutil.copy2(item, target)


class ImageService(api_pb2_grpc.ImageServiceServicer):
    def __init__(self, image_store_dir: str | os.PathLike[str], platform: str = IMAGE_PLATFORM):
        self.image_store_dir = Path(image_store_dir)
        self.platform = platform
        self.images: dict[str, dict[str, Any]] = {}
        self.image_store_dir.mkdir(parents=True, exist_ok=True)
        self.load_images()

    def image_name(self, image_spec) -> str:
        return image_spec.image or image_spec.user_specified_image or image_spec.image_ref

    def normalize_image_ref(self, image: str) -> str:
        return normalize_image_ref(image)

    def image_dir_name(self, image_ref: str) -> str:
        import re

        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", image_ref).strip("_")
        return name or "image"

    def image_path(self, image_ref: str) -> Path:
        return self.image_store_dir / self.image_dir_name(image_ref)

    def metadata_path(self, image_path: Path) -> Path:
        return image_path / IMAGE_METADATA_FILE

    def path_size(self, path: Path) -> int:
        total = 0
        for item in path.rglob("*"):
            if item.is_file():
                total += item.stat().st_size
        return total or DEFAULT_IMAGE_SIZE

    def path_inodes(self, path: Path) -> int:
        return sum(1 for _ in path.rglob("*"))

    def read_metadata(self, image_path: Path) -> dict[str, Any] | None:
        metadata_path = self.metadata_path(image_path)
        if not metadata_path.exists():
            return None
        try:
            with open(metadata_path, "r", encoding="utf-8") as handle:
                data = handle.read()
            return eval(data, {"__builtins__": {}}, {})
        except Exception as exc:  # pragma: no cover - defensive fallback
            logger.warning("Cannot read image metadata %s: %s", metadata_path, exc)
            return None

    def write_metadata(self, img: dict[str, Any]) -> None:
        metadata_path = self.metadata_path(Path(img["path"]))
        with open(metadata_path, "w", encoding="utf-8") as handle:
            handle.write(repr(img))

    def normalize_repo_tags(self, img: dict[str, Any]) -> list[str]:
        repo_tags = img.get("repo_tags") or []
        if repo_tags:
            canonical = [tag for tag in repo_tags if isinstance(tag, str) and tag]
            if canonical:
                return [canonical[0]]
        image_id = img.get("image_id") or img.get("id") or "local:latest"
        return [str(image_id)]

    def load_images(self) -> None:
        for metadata_path in self.image_store_dir.glob(f"*/{IMAGE_METADATA_FILE}"):
            img = self.read_metadata(metadata_path.parent)
            if img is None:
                continue
            img["path"] = str(metadata_path.parent)
            img["size"] = self.path_size(metadata_path.parent)
            img["repo_tags"] = self.normalize_repo_tags(img)
            self.register_image(img)

    def register_image(self, img: dict[str, Any]) -> None:
        self.images[img["id"]] = img
        for tag in img["repo_tags"]:
            self.images[tag] = img
        self.images.setdefault(img["id"], img)

    def unique_images(self) -> list[dict[str, Any]]:
        seen = set()
        result = []
        for img in self.images.values():
            if img["id"] in seen:
                continue
            seen.add(img["id"])
            result.append(img)
        return result

    def find_image(self, image: str) -> dict[str, Any] | None:
        if not image:
            return None
        img = self.images.get(image)
        if img is not None:
            return img
        return self.images.get(self.normalize_image_ref(image))

    def image_response(self, img: dict[str, Any]) -> Any:
        repo_tags = list(img.get("repo_tags") or [])
        if not repo_tags:
            repo_tags = [img.get("id") or "local:latest"]
        primary_tag = repo_tags[0]
        image_id = img.get("image_id") or img.get("id") or primary_tag
        if not str(image_id).startswith("sha256:"):
            digest = hashlib.sha256(primary_tag.encode("utf-8")).hexdigest()
            image_id = f"sha256:{digest[:64]}"
        return api_pb2.Image(
            id=image_id,
            repo_tags=repo_tags,
            size=img["size"],
            spec=api_pb2.ImageSpec(image=primary_tag),
        )

    def matches_filter(self, img: dict[str, Any], filter_obj) -> bool:
        if filter_obj is None:
            return True
        filter_image = self.image_name(filter_obj.image)
        if not filter_image:
            return True
        filter_ref = self.normalize_image_ref(filter_image)
        return filter_image in img["repo_tags"] or filter_ref in img["repo_tags"] or img["id"] == filter_ref

    @log_rpc
    async def ListImages(self, request, context):
        images = [self.image_response(img) for img in self.unique_images() if self.matches_filter(img, request.filter)]
        return api_pb2.ListImagesResponse(images=images)

    async def StreamImages(self, request, context):
        list_response = await self.ListImages(api_pb2.ListImagesRequest(filter=request.filter), context)
        yield api_pb2.StreamImagesResponse(images=list_response.images)

    @log_rpc
    async def ImageStatus(self, request, context):
        image = self.image_name(request.image)
        img = self.find_image(image)
        if img is None:
            return api_pb2.ImageStatusResponse()
        return api_pb2.ImageStatusResponse(image=self.image_response(img))

    @log_rpc
    async def PullImage(self, request, context):
        image = self.image_name(request.image)
        if not image:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "image is required")

        image_ref = self.normalize_image_ref(image)
        out_dir = self.image_path(image_ref)
        try:
            pulled_path = pull_image_to_dir(image=image, output=str(out_dir), platform=self.platform)
        except Exception as exc:
            logger.exception("PullImage failed for %s", image)
            await context.abort(grpc.StatusCode.UNKNOWN, f"pull image failed: {exc}")

        repo_tags = [image_ref]

        img = {
            "id": image_ref,
            "image_id": image_ref,
            "repo_tags": repo_tags,
            "size": self.path_size(Path(pulled_path)),
            "path": str(pulled_path),
        }
        self.write_metadata(img)
        self.register_image(img)
        return api_pb2.PullImageResponse(image_ref=image_ref)

    @log_rpc
    async def RemoveImage(self, request, context):
        image = self.image_name(request.image)
        img = self.find_image(image)
        if img is None:
            return api_pb2.RemoveImageResponse()
        image_path = Path(img["path"])
        if image_path.exists():
            shutil.rmtree(image_path, ignore_errors=True)
        for key, value in list(self.images.items()):
            if value["id"] == img["id"]:
                self.images.pop(key, None)
        return api_pb2.RemoveImageResponse()

    @log_rpc
    async def ImageFsInfo(self, request, context):
        return api_pb2.ImageFsInfoResponse(image_filesystems=[api_pb2.FilesystemUsage(used_bytes=api_pb2.UInt64Value(value=self.path_size(self.image_store_dir)))])


class RuntimeService(api_pb2_grpc.RuntimeServiceServicer):
    def __init__(self, image_store_dir: str | os.PathLike[str], image_platform: str = IMAGE_PLATFORM):
        self.image_store_dir = Path(image_store_dir)
        self.image_platform = image_platform
        self.sandboxes: dict[str, dict[str, Any]] = {}
        self.containers: dict[str, dict[str, Any]] = {}

    def find_sandbox(self, sandbox_id: str) -> dict[str, Any] | None:
        if sandbox_id in self.sandboxes:
            return self.sandboxes[sandbox_id]
        matches = [sb for full_id, sb in self.sandboxes.items() if full_id.startswith(sandbox_id)]
        if len(matches) == 1:
            return matches[0]
        return None

    def find_sandbox_id(self, sandbox_id: str) -> str | None:
        if sandbox_id in self.sandboxes:
            return sandbox_id
        matches = [full_id for full_id in self.sandboxes.keys() if full_id.startswith(sandbox_id)]
        if len(matches) == 1:
            return matches[0]
        return None

    def find_container(self, container_id: str) -> dict[str, Any] | None:
        if container_id in self.containers:
            return self.containers[container_id]
        matches = [c for full_id, c in self.containers.items() if full_id.startswith(container_id)]
        if len(matches) == 1:
            return matches[0]
        return None

    def find_container_id(self, container_id: str) -> str | None:
        if container_id in self.containers:
            return container_id
        matches = [full_id for full_id in self.containers.keys() if full_id.startswith(container_id)]
        if len(matches) == 1:
            return matches[0]
        return None

    def image_rootfs(self, image_ref: str) -> Path | None:
        image_dir = self.image_store_dir / self._image_dir_name(image_ref)
        if image_dir.exists():
            return image_dir
        return None

    def _image_dir_name(self, image_ref: str) -> str:
        import re

        name = re.sub(r"[^A-Za-z0-9_.-]+", "_", image_ref).strip("_")
        return name or "image"

    def build_command(self, container: dict[str, Any]) -> list[str]:
        command = list(container["command"]) + list(container["args"])
        if not command:
            return ["/bin/sh"]
        return command

    def resolve_command(self, command: list[str], container: dict[str, Any]) -> list[str]:
        image_ref = container.get("image_ref") or ""
        rootfs = self.image_rootfs(image_ref)
        if rootfs is None:
            return command

        resolved = []
        for item in command:
            candidate = None
            if os.path.isabs(item):
                candidate = rootfs / item.lstrip("/")
            else:
                candidate = rootfs / item
            if candidate.exists():
                resolved.append(str(candidate))
            else:
                resolved.append(item)
        return resolved

    @log_rpc
    async def Version(self, request, context):
        return api_pb2.VersionResponse(version="0.1.0", runtime_name="pnfroot", runtime_version="0.1.0", runtime_api_version="v1")

    @log_rpc
    async def Status(self, request, context):
        return api_pb2.StatusResponse(
            status=api_pb2.RuntimeStatus(
                conditions=[
                    api_pb2.RuntimeCondition(type="RuntimeReady", status=True, reason="RuntimeReady", message="runtime is ready"),
                    api_pb2.RuntimeCondition(type="NetworkReady", status=True, reason="NetworkReady", message="network is ready"),
                ]
            )
        )

    @log_rpc
    async def RuntimeConfig(self, request, context):
        return api_pb2.RuntimeConfigResponse(linux=api_pb2.LinuxRuntimeConfiguration(cgroup_driver=api_pb2.CGROUPFS))

    @log_rpc
    async def RunPodSandbox(self, request, context):
        pod_id = uuid.uuid4().hex
        self.sandboxes[pod_id] = {
            "id": pod_id,
            "metadata": request.config.metadata,
            "state": api_pb2.SANDBOX_READY,
            "created_at": int(time.time() * 1_000_000_000),
            "labels": request.config.labels,
            "annotations": request.config.annotations,
            "runtime_handler": request.runtime_handler,
        }
        return api_pb2.RunPodSandboxResponse(pod_sandbox_id=pod_id)

    @log_rpc
    async def StopPodSandbox(self, request, context):
        full_id = self.find_sandbox_id(request.pod_sandbox_id)
        if full_id is None:
            return api_pb2.StopPodSandboxResponse()
        for container in self.containers.values():
            if container["pod_sandbox_id"] != full_id:
                continue
            process = container.get("process")
            if process is not None and process.poll() is None:
                process.terminate()
            container["state"] = api_pb2.CONTAINER_EXITED
            container["finished_at"] = time.time_ns()
        self.sandboxes[full_id]["state"] = api_pb2.SANDBOX_NOTREADY
        return api_pb2.StopPodSandboxResponse()

    @log_rpc
    async def RemovePodSandbox(self, request, context):
        full_id = self.find_sandbox_id(request.pod_sandbox_id)
        if full_id is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "sandbox not found")
        self.sandboxes.pop(full_id, None)
        return api_pb2.RemovePodSandboxResponse()

    @log_rpc
    async def PodSandboxStatus(self, request, context):
        sandbox = self.find_sandbox(request.pod_sandbox_id)
        if sandbox is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "sandbox not found")
        return api_pb2.PodSandboxStatusResponse(
            status=api_pb2.PodSandboxStatus(
                id=sandbox["id"],
                metadata=sandbox["metadata"],
                state=sandbox["state"],
                created_at=sandbox["created_at"],
                network=api_pb2.PodSandboxNetworkStatus(ip="127.0.0.1"),
                labels=sandbox["labels"],
                annotations=sandbox["annotations"],
                runtime_handler=sandbox["runtime_handler"],
            )
        )

    @log_rpc
    async def ListPodSandbox(self, request, context):
        items = []
        filter_obj = request.filter
        for pod_id, sandbox in self.sandboxes.items():
            if filter_obj is not None:
                if filter_obj.id and not pod_id.startswith(filter_obj.id):
                    continue
                if filter_obj.HasField("state") and sandbox["state"] != filter_obj.state.state:
                    continue
                if not labels_match(sandbox["labels"], filter_obj.label_selector):
                    continue
            items.append(
                api_pb2.PodSandbox(
                    id=pod_id,
                    metadata=sandbox["metadata"],
                    state=sandbox["state"],
                    created_at=sandbox["created_at"],
                    labels=sandbox["labels"],
                    annotations=sandbox["annotations"],
                    runtime_handler=sandbox["runtime_handler"],
                )
            )
        return api_pb2.ListPodSandboxResponse(items=items)

    @log_rpc
    async def CreateContainer(self, request, context):
        sandbox_id = self.find_sandbox_id(request.pod_sandbox_id)
        if sandbox_id is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "sandbox not found")

        container_id = uuid.uuid4().hex
        config = request.config
        image_name = config.image.image if config.image and config.image.image else ""
        image_ref = normalize_image_ref(image_name) if image_name else ""

        self.containers[container_id] = {
            "id": container_id,
            "pod_sandbox_id": sandbox_id,
            "metadata": config.metadata,
            "image": config.image,
            "image_ref": image_ref,
            "command": list(config.command) if config.command else [],
            "args": list(config.args) if config.args else [],
            "working_dir": config.working_dir or None,
            "log_path": f"{container_id}.log",
            "envs": {env.key: env.value for env in config.envs} if config.envs else {},
            "state": api_pb2.CONTAINER_CREATED,
            "created_at": int(time.time() * 1_000_000_000),
            "started_at": 0,
            "finished_at": 0,
            "exit_code": 0,
            "labels": config.labels,
            "annotations": config.annotations,
            "image_id": image_ref,
            "process": None,
        }
        return api_pb2.CreateContainerResponse(container_id=container_id)

    @log_rpc
    async def StartContainer(self, request, context):
        container = self.find_container(request.container_id)
        if container is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "container not found")

        if container.get("process") is None or container["process"].poll() is not None:
            command = self.resolve_command(self.build_command(container), container)
            log_dir = Path("/tmp/pnfroot")
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = str(log_dir / f"{container['id']}.log")
            env = os.environ.copy()
            env.update(container["envs"])
            if container.get("working_dir"):
                work_dir = container["working_dir"]
            else:
                work_dir = str(self.image_rootfs(container.get("image_ref") or "") or Path.cwd())
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=work_dir,
                env=env,
            )
            container["process"] = process
            container["log_path"] = log_path
            threading.Thread(target=pipe_to_cri_log, args=(process.stdout, log_path, "stdout"), daemon=True).start()
            threading.Thread(target=pipe_to_cri_log, args=(process.stderr, log_path, "stderr"), daemon=True).start()

        container["state"] = api_pb2.CONTAINER_RUNNING
        if container["started_at"] == 0:
            container["started_at"] = int(time.time() * 1_000_000_000)
        return api_pb2.StartContainerResponse()

    @log_rpc
    async def StopContainer(self, request, context):
        cid = self.find_container_id(request.container_id)
        container = self.containers.get(cid)
        if container is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "container not found")
        process = container.get("process")
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=request.timeout or 10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        container["state"] = api_pb2.CONTAINER_EXITED
        container["finished_at"] = int(time.time() * 1_000_000_000)
        container["exit_code"] = 0
        return api_pb2.StopContainerResponse()

    @log_rpc
    async def RemoveContainer(self, request, context):
        cid = self.find_container_id(request.container_id)
        if cid is None:
            return api_pb2.RemoveContainerResponse()
        container = self.containers.get(cid)
        if container is not None:
            process = container.get("process")
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
        self.containers.pop(cid, None)
        return api_pb2.RemoveContainerResponse()

    @log_rpc
    async def ListContainers(self, request, context):
        items = []
        filter_obj = request.filter
        for container in self.containers.values():
            if filter_obj is not None:
                if filter_obj.id and not container["id"].startswith(filter_obj.id):
                    continue
                if filter_obj.pod_sandbox_id and not container["pod_sandbox_id"].startswith(filter_obj.pod_sandbox_id):
                    continue
                if filter_obj.HasField("state") and filter_obj.state.state != container["state"]:
                    continue
                if not labels_match(container["labels"], filter_obj.label_selector):
                    continue
            items.append(
                api_pb2.Container(
                    id=container["id"],
                    pod_sandbox_id=container["pod_sandbox_id"],
                    metadata=container["metadata"],
                    image=container["image"],
                    image_ref=container["image_ref"],
                    state=container["state"],
                    created_at=container["created_at"],
                    labels=container["labels"],
                    annotations=container["annotations"],
                    image_id=container["image_id"],
                )
            )
        return api_pb2.ListContainersResponse(containers=items)

    @log_rpc
    async def ContainerStatus(self, request, context):
        container = self.find_container(request.container_id)
        if container is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "container not found")
        status = api_pb2.ContainerStatus(
            id=container["id"],
            metadata=container["metadata"],
            state=container["state"],
            created_at=container["created_at"],
            started_at=container["started_at"],
            finished_at=container["finished_at"],
            exit_code=container["exit_code"],
            image=container["image"],
            image_ref=container["image_ref"],
            reason="Running" if container["state"] == api_pb2.CONTAINER_RUNNING else "Created",
            message="",
            labels=container["labels"],
            annotations=container["annotations"],
            image_id=container["image_id"],
            log_path=container["log_path"],
        )
        return api_pb2.ContainerStatusResponse(status=status)

    @log_rpc
    async def ExecSync(self, request, context):
        container = self.find_container(request.container_id)
        if container is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "container not found")
        try:
            result = subprocess.run(
                list(request.cmd),
                capture_output=True,
                timeout=request.timeout or 10,
                env={**os.environ, **container["envs"]} if container["envs"] else None,
                cwd=container["working_dir"] or None,
            )
            return api_pb2.ExecSyncResponse(stdout=result.stdout, stderr=result.stderr, exit_code=result.returncode)
        except subprocess.TimeoutExpired as exc:
            return api_pb2.ExecSyncResponse(stdout=exc.stdout or b"", stderr=exc.stderr or b"timeout", exit_code=124)

    @log_rpc
    async def Exec(self, request, context):
        container = self.find_container(request.container_id)
        if container is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "container not found")
        return api_pb2.ExecResponse(url="")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket-path", default=SOCKET_PATH)
    parser.add_argument("--image-store-dir", default=IMAGE_STORE_DIR)
    parser.add_argument("--image-platform", default=IMAGE_PLATFORM)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    configure_logging(args.verbose)

    if os.path.exists(args.socket_path):
        os.remove(args.socket_path)

    server = grpc.aio.server()
    api_pb2_grpc.add_RuntimeServiceServicer_to_server(
        RuntimeService(image_store_dir=args.image_store_dir, image_platform=args.image_platform),
        server,
    )
    api_pb2_grpc.add_ImageServiceServicer_to_server(
        ImageService(image_store_dir=args.image_store_dir, platform=args.image_platform),
        server,
    )
    server.add_insecure_port(f"unix://{args.socket_path}")
    await server.start()

    logger.info("CRI server started on unix://%s", args.socket_path)
    logger.info("Image store dir: %s", args.image_store_dir)
    logger.info("Image platform: %s", args.image_platform)
    await server.wait_for_termination()


if __name__ == "__main__":
    asyncio.run(main())
