#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import base64
import fcntl
import json
import os
import signal
import shutil
import subprocess
import termios
import threading
import time
import uuid
import warnings
from pathlib import Path
from typing import Any

import grpc

from cri_common import configure_logging, labels_match, log_rpc, logger, normalize_image_ref
# Compatibility re-exports: tests and local scripts import these helpers from pnfroot.
from image_store import (
    DEFAULT_IMAGE_SIZE,
    IMAGE_METADATA_FILE,
    IMAGE_PLATFORM,
    REGISTRY_LAYER_MEDIA_TYPES,
    REGISTRY_MANIFEST_ACCEPT,
    RegistryClient,
    blob_path,
    cri_time_ns,
    extract_tar_safe,
    image_dir_has_layers,
    image_dir_name,
    image_metadata,
    manifest_is_index,
    parse_image_reference_for_registry,
    parse_www_authenticate,
    path_size,
    platform_parts,
    pull_image_to_store,
    pull_registry_image_to_store,
    read_image_metadata,
    registry_scheme,
    select_platform_manifest,
    sha256_bytes,
    sha256_file,
    unpack_image_to_rootfs,
    write_blob_bytes,
    write_blob_payload,
    write_image_metadata,
)
from image_service import ImageService
import ptrace_syscalls
# Compatibility re-exports for CRI streaming constants/classes.
from streaming import (
    CHANNEL_PROTOCOLS,
    ExecStreamRequest,
    RemoteCommandHTTPServer,
    RemoteCommandRequestHandler,
    RemoteCommandServer,
    SPDY_FLAG_FIN,
    SPDY_HEADER_DICTIONARY,
    SPDY_STATUS_CANCEL,
    SPDY_TYPE_GOAWAY,
    SPDY_TYPE_HEADERS,
    SPDY_TYPE_PING,
    SPDY_TYPE_RST_STREAM,
    SPDY_TYPE_SETTINGS,
    SPDY_TYPE_SYN_REPLY,
    SPDY_TYPE_SYN_STREAM,
    SPDY_TYPE_WINDOW_UPDATE,
    SPDY_UPGRADE,
    SPDY_VERSION,
    STREAM_CLOSE,
    STREAM_ERROR,
    STREAM_HOST,
    STREAM_PORT,
    STREAM_RESIZE,
    STREAM_STDERR,
    STREAM_STDIN,
    STREAM_STDOUT,
    STREAM_TOKEN_TTL_SECONDS,
    SpdyRemoteCommandConnection,
    WebSocketConnection,
    WEBSOCKET_GUID,
    WEBSOCKET_PROTOCOLS,
)
import tools.api_pb2 as api_pb2
import tools.api_pb2_grpc as api_pb2_grpc


ROOT = Path(__file__).resolve().parent
SOCKET_PATH = "/tmp/pnfroot.sock"
IMAGE_STORE_DIR = "/tmp/pnfroot/images"
CONTAINER_STORE_DIR = "/tmp/pnfroot/containers"
ROOTFS_METADATA_FILE = "pnfroot-rootfs.json"
RUNTIME_STATE_FILE = "pnfroot-runtime-state.json"


def pipe_to_cri_log(pipe, log_path: str, stream: str) -> None:
    with open(log_path, "ab", buffering=0) as handle:
        for line in iter(pipe.readline, b""):
            ts = cri_time_ns().encode()
            handle.write(ts + b" " + stream.encode() + b" F " + line)


def encode_proto(message: Any | None) -> str:
    if message is None:
        return ""
    return base64.b64encode(message.SerializeToString()).decode("ascii")


def decode_proto(message_cls: Any, payload: str | None) -> Any:
    message = message_cls()
    if payload:
        message.ParseFromString(base64.b64decode(payload.encode("ascii")))
    return message


def env_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="surrogateescape")
    return str(value)


def normalize_envs(envs: Any) -> dict[str, str]:
    if not envs:
        return {}

    if hasattr(envs, "items"):
        items = envs.items()
    else:
        items = ((env.key, env.value) for env in envs)

    return {env_text(key): env_text(value) for key, value in items}


def process_status_to_returncode(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return 0


class ContainerizedProcess:
    def __init__(
        self,
        pid: int,
        *,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
    ):
        self.pid = pid
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None
        self._wait_lock = threading.Lock()

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        with self._wait_lock:
            if self.returncode is not None:
                return self.returncode
            try:
                waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                self.returncode = 0
                return self.returncode
            if waited_pid == 0:
                return None
            self.returncode = process_status_to_returncode(status)
            return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is not None:
            return self.returncode
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            with self._wait_lock:
                if self.returncode is not None:
                    return self.returncode
                try:
                    waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
                except ChildProcessError:
                    self.returncode = 0
                    return self.returncode
                if waited_pid:
                    self.returncode = process_status_to_returncode(status)
                    return self.returncode
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired([self.pid], timeout)
            time.sleep(0.01)

    def terminate(self) -> None:
        self._signal(signal.SIGTERM)

    def kill(self) -> None:
        self._signal(signal.SIGKILL)

    def _signal(self, sig: int) -> None:
        if self.poll() is not None:
            return
        try:
            os.killpg(self.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            try:
                os.kill(self.pid, sig)
            except OSError:
                pass


def find_unique_prefix_key(items: dict[str, Any], item_id: str) -> str | None:
    if item_id in items:
        return item_id
    matches = [full_id for full_id in items.keys() if full_id.startswith(item_id)]
    if len(matches) == 1:
        return matches[0]
    return None


def find_unique_prefix_value(items: dict[str, Any], item_id: str) -> Any | None:
    full_id = find_unique_prefix_key(items, item_id)
    if full_id is None:
        return None
    return items[full_id]


class RuntimeService(api_pb2_grpc.RuntimeServiceServicer):
    def __init__(
        self,
        image_store_dir: str | os.PathLike[str],
        container_store_dir: str | os.PathLike[str] = CONTAINER_STORE_DIR,
        image_platform: str = IMAGE_PLATFORM,
        stream_host: str = STREAM_HOST,
        stream_port: int = STREAM_PORT,
        stream_public_host: str | None = None,
    ):
        self.image_store_dir = Path(image_store_dir)
        self.container_store_dir = Path(container_store_dir)
        self.image_platform = image_platform
        self.image_store_dir.mkdir(parents=True, exist_ok=True)
        self.container_store_dir.mkdir(parents=True, exist_ok=True)
        self.sandboxes: dict[str, dict[str, Any]] = {}
        self.containers: dict[str, dict[str, Any]] = {}
        self._state_lock = threading.RLock()
        self._stream_host = stream_host
        self._stream_port = stream_port
        self._stream_public_host = stream_public_host
        self._stream_server: RemoteCommandServer | None = None
        self.load_runtime_state()

    @property
    def stream_server(self) -> RemoteCommandServer:
        if self._stream_server is None:
            self._stream_server = RemoteCommandServer(
                self,
                host=self._stream_host,
                port=self._stream_port,
                public_host=self._stream_public_host,
            )
        return self._stream_server

    def shutdown_stream_server(self) -> None:
        if self._stream_server is None:
            return
        self._stream_server.shutdown()
        self._stream_server = None

    def runtime_state_path(self) -> Path:
        return self.container_store_dir / RUNTIME_STATE_FILE

    def sandbox_to_state(self, sandbox: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": sandbox["id"],
            "metadata": encode_proto(sandbox.get("metadata")),
            "state": int(sandbox.get("state", api_pb2.SANDBOX_NOTREADY)),
            "created_at": int(sandbox.get("created_at", 0)),
            "labels": dict(sandbox.get("labels") or {}),
            "annotations": dict(sandbox.get("annotations") or {}),
            "runtime_handler": sandbox.get("runtime_handler") or "",
        }

    def sandbox_from_state(self, data: dict[str, Any]) -> dict[str, Any]:
        sandbox_id = str(data["id"])
        return {
            "id": sandbox_id,
            "metadata": decode_proto(api_pb2.PodSandboxMetadata, data.get("metadata")),
            "state": int(data.get("state", api_pb2.SANDBOX_NOTREADY)),
            "created_at": int(data.get("created_at", 0)),
            "labels": dict(data.get("labels") or {}),
            "annotations": dict(data.get("annotations") or {}),
            "runtime_handler": data.get("runtime_handler") or "",
        }

    def container_to_state(self, container: dict[str, Any]) -> dict[str, Any]:
        rootfs_status = container.get("rootfs_status")
        if rootfs_status == "preparing":
            rootfs_status = None
        start_status = container.get("start_status")
        if start_status == "starting":
            start_status = None
        return {
            "id": container["id"],
            "pod_sandbox_id": container.get("pod_sandbox_id") or "",
            "metadata": encode_proto(container.get("metadata")),
            "image": encode_proto(container.get("image")),
            "image_ref": container.get("image_ref") or "",
            "command": list(container.get("command") or []),
            "args": list(container.get("args") or []),
            "working_dir": container.get("working_dir") or "",
            "log_path": container.get("log_path") or f"{container['id']}.log",
            "envs": normalize_envs(container.get("envs")),
            "state": int(container.get("state", api_pb2.CONTAINER_CREATED)),
            "created_at": int(container.get("created_at", 0)),
            "started_at": int(container.get("started_at", 0)),
            "finished_at": int(container.get("finished_at", 0)),
            "exit_code": int(container.get("exit_code", 0)),
            "labels": dict(container.get("labels") or {}),
            "annotations": dict(container.get("annotations") or {}),
            "image_id": container.get("image_id") or "",
            "bundle_path": container.get("bundle_path") or str(self.container_store_dir / container["id"]),
            "rootfs_path": container.get("rootfs_path") or str(self.container_store_dir / container["id"] / "rootfs"),
            "rootfs_status": rootfs_status or "",
            "rootfs_error": container.get("rootfs_error") or "",
            "start_status": start_status or "",
            "start_error": container.get("start_error") or "",
        }

    def container_from_state(self, data: dict[str, Any]) -> dict[str, Any]:
        container_id = str(data["id"])
        state = int(data.get("state", api_pb2.CONTAINER_CREATED))
        finished_at = int(data.get("finished_at", 0))
        exit_code = int(data.get("exit_code", 0))
        start_status = data.get("start_status") or None
        if state == api_pb2.CONTAINER_RUNNING:
            state = api_pb2.CONTAINER_EXITED
            finished_at = finished_at or time.time_ns()
            start_status = "recovered"
        rootfs_status = data.get("rootfs_status") or None
        if rootfs_status == "preparing":
            rootfs_status = None
        bundle_path = data.get("bundle_path") or str(self.container_store_dir / container_id)
        rootfs_path = data.get("rootfs_path") or str(Path(bundle_path) / "rootfs")
        return {
            "id": container_id,
            "pod_sandbox_id": data.get("pod_sandbox_id") or "",
            "metadata": decode_proto(api_pb2.ContainerMetadata, data.get("metadata")),
            "image": decode_proto(api_pb2.ImageSpec, data.get("image")),
            "image_ref": data.get("image_ref") or "",
            "command": list(data.get("command") or []),
            "args": list(data.get("args") or []),
            "working_dir": data.get("working_dir") or None,
            "log_path": data.get("log_path") or f"{container_id}.log",
            "envs": normalize_envs(data.get("envs")),
            "state": state,
            "created_at": int(data.get("created_at", 0)),
            "started_at": int(data.get("started_at", 0)),
            "finished_at": finished_at,
            "exit_code": exit_code,
            "labels": dict(data.get("labels") or {}),
            "annotations": dict(data.get("annotations") or {}),
            "image_id": data.get("image_id") or data.get("image_ref") or "",
            "process": None,
            "bundle_path": str(bundle_path),
            "rootfs_path": str(rootfs_path),
            "rootfs_status": rootfs_status,
            "rootfs_error": data.get("rootfs_error") or "",
            "start_status": start_status,
            "start_error": data.get("start_error") or "",
            "stop_requested": False,
        }

    def load_runtime_state(self) -> None:
        state_path = self.runtime_state_path()
        if not state_path.exists():
            return
        try:
            with open(state_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Cannot read runtime state %s: %s", state_path, exc)
            return

        sandboxes = payload.get("sandboxes") or []
        containers = payload.get("containers") or []
        if isinstance(sandboxes, dict):
            sandboxes = sandboxes.values()
        if isinstance(containers, dict):
            containers = containers.values()

        loaded_sandboxes = 0
        for data in sandboxes:
            try:
                sandbox = self.sandbox_from_state(data)
            except Exception as exc:
                logger.warning("Skipping invalid sandbox state in %s: %s", state_path, exc)
                continue
            self.sandboxes[sandbox["id"]] = sandbox
            loaded_sandboxes += 1

        loaded_containers = 0
        for data in containers:
            try:
                container = self.container_from_state(data)
            except Exception as exc:
                logger.warning("Skipping invalid container state in %s: %s", state_path, exc)
                continue
            self.containers[container["id"]] = container
            loaded_containers += 1

        if loaded_sandboxes or loaded_containers:
            logger.info(
                "Loaded runtime state: %s sandboxes, %s containers",
                loaded_sandboxes,
                loaded_containers,
            )
            self.save_runtime_state()

    def save_runtime_state(self) -> None:
        with self._state_lock:
            state_path = self.runtime_state_path()
            state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "saved_at": cri_time_ns(),
                "sandboxes": [self.sandbox_to_state(sandbox) for sandbox in self.sandboxes.values()],
                "containers": [self.container_to_state(container) for container in self.containers.values()],
            }
            tmp_path = state_path.with_name(f".{state_path.name}.{uuid.uuid4().hex}.tmp")
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
            os.replace(tmp_path, state_path)

    def find_sandbox(self, sandbox_id: str) -> dict[str, Any] | None:
        return find_unique_prefix_value(self.sandboxes, sandbox_id)

    def find_sandbox_id(self, sandbox_id: str) -> str | None:
        return find_unique_prefix_key(self.sandboxes, sandbox_id)

    def find_container(self, container_id: str) -> dict[str, Any] | None:
        return find_unique_prefix_value(self.containers, container_id)

    def find_container_id(self, container_id: str) -> str | None:
        return find_unique_prefix_key(self.containers, container_id)

    def image_path(self, image_ref: str) -> Path:
        return self.image_store_dir / self._image_dir_name(image_ref)

    def image_available(self, image_ref: str) -> bool:
        image_path = self.image_path(image_ref)
        return image_path.exists() and image_dir_has_layers(image_path)

    def image_cache_needs_refresh(self, image_ref: str, image_name: str | None = None) -> bool:
        image = image_name or image_ref
        if not image:
            return False
        img = read_image_metadata(self.image_path(image_ref)) or {}
        return img.get("source_type") != "registry"

    def ensure_image_pulled(self, image_ref: str, image_name: str | None = None) -> Path | None:
        if not image_ref:
            return None
        image_path = self.image_path(image_ref)
        if self.image_available(image_ref):
            if self.image_cache_needs_refresh(image_ref, image_name):
                logger.info("Refreshing legacy image cache for registry image %s", image_name or image_ref)
                shutil.rmtree(image_path, ignore_errors=True)
            else:
                return image_path
        if self.image_available(image_ref):
            return image_path
        if image_path.exists() and not self.image_available(image_ref):
            shutil.rmtree(image_path, ignore_errors=True)
        source = image_name or image_ref
        pull_image_to_store(source, image_store_dir=self.image_store_dir, platform=self.image_platform)
        return image_path if self.image_available(image_ref) else None

    def container_bundle_path(self, container: dict[str, Any]) -> Path:
        bundle_path = container.get("bundle_path")
        if bundle_path:
            return Path(bundle_path)
        return self.container_store_dir / container["id"]

    def container_rootfs_path(self, container: dict[str, Any]) -> Path:
        rootfs_path = container.get("rootfs_path")
        if rootfs_path:
            return Path(rootfs_path)
        return self.container_bundle_path(container) / "rootfs"

    def container_rootfs_metadata_path(self, container: dict[str, Any]) -> Path:
        return self.container_bundle_path(container) / ROOTFS_METADATA_FILE

    def read_container_rootfs_metadata(self, container: dict[str, Any]) -> dict[str, Any] | None:
        metadata_path = self.container_rootfs_metadata_path(container)
        if not metadata_path.exists():
            return None
        try:
            with open(metadata_path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None

    def rootfs_matches_image(self, container: dict[str, Any], image_path: Path) -> bool:
        rootfs = self.container_rootfs_path(container)
        if not rootfs.exists() or not any(rootfs.iterdir()):
            return False
        img = read_image_metadata(image_path) or {}
        metadata = self.read_container_rootfs_metadata(container)
        if metadata is None:
            return False
        return (
            metadata.get("image_ref") == container.get("image_ref")
            and metadata.get("image_id") == img.get("image_id")
            and metadata.get("layer_digests") == img.get("layer_digests")
        )

    def write_container_rootfs_metadata(self, container: dict[str, Any], image_path: Path) -> None:
        img = read_image_metadata(image_path) or {}
        metadata_path = self.container_rootfs_metadata_path(container)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        with open(metadata_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "image_ref": container.get("image_ref"),
                    "image_id": img.get("image_id"),
                    "layer_digests": img.get("layer_digests") or [],
                    "created_at": cri_time_ns(),
                },
                handle,
                separators=(",", ":"),
                sort_keys=True,
            )

    def container_rootfs(self, container: dict[str, Any]) -> Path | None:
        rootfs = self.container_rootfs_path(container)
        if rootfs.exists():
            return rootfs
        return None

    def container_rootfs_condition(self, container: dict[str, Any]) -> threading.Condition:
        condition = container.get("rootfs_condition")
        if condition is None:
            condition = threading.Condition()
            container["rootfs_condition"] = condition
        return condition

    def container_start_condition(self, container: dict[str, Any]) -> threading.Condition:
        condition = container.get("start_condition")
        if condition is None:
            condition = threading.Condition()
            container["start_condition"] = condition
        return condition

    def prepare_container_rootfs_async(self, container: dict[str, Any]) -> None:
        if not container.get("image_ref"):
            return
        condition = self.container_rootfs_condition(container)
        with condition:
            if container.get("rootfs_status") in {"preparing", "ready", "fallback"}:
                return
            container["rootfs_status"] = "preparing"
            thread = threading.Thread(
                target=self._prepare_container_rootfs,
                args=(container,),
                name=f"pnfroot-rootfs-{container['id'][:12]}",
                daemon=True,
            )
            container["rootfs_thread"] = thread
            thread.start()

    def _prepare_container_rootfs(self, container: dict[str, Any]) -> None:
        condition = self.container_rootfs_condition(container)
        try:
            rootfs = self.ensure_container_rootfs(container)
            with condition:
                container["rootfs_error"] = ""
                container["rootfs_status"] = "ready" if rootfs is not None else "fallback"
                condition.notify_all()
            self.save_runtime_state()
        except BaseException as exc:
            logger.exception("Cannot prepare rootfs for container %s", container.get("id"))
            with condition:
                container["rootfs_error"] = str(exc)
                container["rootfs_status"] = "error"
                condition.notify_all()
            self.save_runtime_state()

    def wait_for_container_rootfs(self, container: dict[str, Any]) -> Path | None:
        if not container.get("image_ref"):
            return None
        condition = self.container_rootfs_condition(container)
        with condition:
            needs_prepare = container.get("rootfs_status") is None
        if needs_prepare:
            self.prepare_container_rootfs_async(container)
        with condition:
            while container.get("rootfs_status") == "preparing":
                condition.wait(timeout=0.1)
            status = container.get("rootfs_status")
            if status == "error":
                raise RuntimeError(container.get("rootfs_error") or "rootfs preparation failed")
        image_path = self.image_path(container.get("image_ref") or "")
        if status == "ready" and self.container_rootfs_path(container).exists():
            return self.container_rootfs_path(container)
        if self.rootfs_matches_image(container, image_path):
            return self.container_rootfs_path(container)
        if status == "fallback":
            return None
        return self.ensure_container_rootfs(container)

    def ensure_container_rootfs(self, container: dict[str, Any]) -> Path | None:
        image_ref = container.get("image_ref") or ""
        image_path = self.ensure_image_pulled(image_ref, self.container_image_name(container))
        if image_path is None:
            return None
        rootfs = self.container_rootfs_path(container)
        if self.rootfs_matches_image(container, image_path):
            return rootfs
        rootfs.parent.mkdir(parents=True, exist_ok=True)
        unpack_image_to_rootfs(image_path, rootfs)
        self.write_container_rootfs_metadata(container, image_path)
        return rootfs

    def _image_dir_name(self, image_ref: str) -> str:
        return image_dir_name(image_ref)

    def build_command(self, container: dict[str, Any]) -> list[str]:
        command = list(container["command"]) + list(container["args"])
        if not command:
            return ["/bin/sh"]
        return command

    def container_image_name(self, container: dict[str, Any]) -> str:
        image = container.get("image")
        if image is None:
            return container.get("image_ref") or ""
        return image.image or image.user_specified_image or image.image_ref or container.get("image_ref") or ""

    def resolve_command(self, command: list[str], container: dict[str, Any]) -> list[str]:
        rootfs = self.container_rootfs(container)
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

    def container_virtual_cwd(self, container: dict[str, Any]) -> str:
        working_dir = container.get("working_dir")
        if not working_dir:
            return "/"
        if os.path.isabs(working_dir):
            return os.path.normpath(working_dir)
        return os.path.normpath("/" + working_dir)

    def container_env(self, container: dict[str, Any]) -> dict[str, str]:
        env = {
            "HOME": "/root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": os.environ.get("TERM", "xterm-256color"),
        }
        env.update(normalize_envs(container.get("envs")))
        return env

    def container_cwd(self, container: dict[str, Any]) -> str:
        rootfs = self.container_rootfs(container)
        working_dir = self.container_virtual_cwd(container)
        if rootfs is not None:
            return str(rootfs / working_dir.lstrip("/"))
        if working_dir != "/":
            return str(working_dir)
        return str(rootfs or Path.cwd())

    def container_subprocess_cwd(self, container: dict[str, Any]) -> str:
        if self.container_rootfs(container) is not None:
            return str(ROOT)
        return self.container_cwd(container)

    def close_fds(self, *fds: int | None) -> None:
        for fd in set(fds) - {None}:
            try:
                os.close(fd)
            except OSError:
                pass

    def start_process(
        self,
        container: dict[str, Any],
        command: list[str],
        *,
        tty: bool = False,
        stdin: bool = False,
        stdout: bool = False,
        stderr: bool = False,
    ) -> tuple[subprocess.Popen[bytes] | ContainerizedProcess, int | None]:
        rootfs = self.wait_for_container_rootfs(container)
        if rootfs is None:
            return self.start_host_process(
                container,
                command,
                tty=tty,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
            )
        return self.start_containerized_process(
            container,
            command,
            rootfs=rootfs,
            tty=tty,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )

    def start_host_process(
        self,
        container: dict[str, Any],
        command: list[str],
        *,
        tty: bool,
        stdin: bool,
        stdout: bool,
        stderr: bool,
    ) -> tuple[subprocess.Popen[bytes], int | None]:
        command = self.resolve_command(command, container)
        env = self.container_env(container)
        cwd = self.container_subprocess_cwd(container)
        if tty:
            master_fd, slave_fd = os.openpty()
            def prepare_tty() -> None:
                os.setsid()
                fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

            try:
                process = subprocess.Popen(
                    command,
                    stdin=slave_fd,
                    stdout=slave_fd,
                    stderr=slave_fd,
                    cwd=cwd,
                    env=env,
                    close_fds=True,
                    preexec_fn=prepare_tty,
                )
            finally:
                os.close(slave_fd)
            return process, master_fd

        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
            stdout=subprocess.PIPE if stdout else subprocess.DEVNULL,
            stderr=subprocess.PIPE if stderr else subprocess.DEVNULL,
            cwd=cwd,
            env=env,
        )
        return process, None

    def start_containerized_process(
        self,
        container: dict[str, Any],
        command: list[str],
        *,
        rootfs: Path,
        tty: bool,
        stdin: bool,
        stdout: bool,
        stderr: bool,
    ) -> tuple[ContainerizedProcess, int | None]:
        stdin_read = stdin_write = None
        stdout_read = stdout_write = None
        stderr_read = stderr_write = None
        pty_master = pty_slave = None
        stdin_file = stdout_file = stderr_file = None

        try:
            if tty:
                pty_master, pty_slave = os.openpty()
                child_stdin = pty_slave
                child_stdout = pty_slave
                child_stderr = pty_slave
            else:
                if stdin:
                    stdin_read, stdin_write = os.pipe()
                    child_stdin = stdin_read
                else:
                    child_stdin = os.open(os.devnull, os.O_RDONLY)

                if stdout:
                    stdout_read, stdout_write = os.pipe()
                    child_stdout = stdout_write
                else:
                    child_stdout = os.open(os.devnull, os.O_WRONLY)

                if stderr:
                    stderr_read, stderr_write = os.pipe()
                    child_stderr = stderr_write
                else:
                    child_stderr = os.open(os.devnull, os.O_WRONLY)

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                supervisor_pid = os.fork()
            if supervisor_pid == 0:
                try:
                    os.setsid()
                    self.close_fds(stdin_write, stdout_read, stderr_read, pty_master)
                    exit_code = ptrace_syscalls.run_tracee(
                        command,
                        rootfs_path=str(rootfs),
                        cwd=self.container_virtual_cwd(container),
                        env=self.container_env(container),
                        stdin_fd=child_stdin,
                        stdout_fd=child_stdout,
                        stderr_fd=child_stderr,
                        controlling_tty=tty,
                    )
                    os._exit(exit_code)
                except BaseException as exc:
                    os.write(2, f"pnfroot trace supervisor failed: {exc}\n".encode("utf-8", "replace"))
                    os._exit(125)

            self.close_fds(child_stdin, child_stdout, child_stderr, pty_slave)
            if stdin_write is not None:
                stdin_file = os.fdopen(stdin_write, "wb", buffering=0)
            if stdout_read is not None:
                stdout_file = os.fdopen(stdout_read, "rb", buffering=0)
            if stderr_read is not None:
                stderr_file = os.fdopen(stderr_read, "rb", buffering=0)
            return (
                ContainerizedProcess(
                    supervisor_pid,
                    stdin=stdin_file,
                    stdout=stdout_file,
                    stderr=stderr_file,
                ),
                pty_master,
            )
        except Exception:
            for handle in (stdin_file, stdout_file, stderr_file):
                if handle is not None:
                    try:
                        handle.close()
                    except OSError:
                        pass
            self.close_fds(
                stdin_read,
                stdin_write,
                stdout_read,
                stdout_write,
                stderr_read,
                stderr_write,
                pty_master,
                pty_slave,
            )
            raise

    def refresh_container_state(self, container: dict[str, Any]) -> None:
        process = container.get("process")
        if process is None or process.poll() is None:
            return
        previous_state = container.get("state")
        container["state"] = api_pb2.CONTAINER_EXITED
        container["finished_at"] = container["finished_at"] or int(time.time() * 1_000_000_000)
        container["exit_code"] = process.returncode or 0
        if previous_state != container["state"]:
            self.save_runtime_state()

    def start_exec_process(
        self,
        container: dict[str, Any],
        command: list[str],
        *,
        tty: bool,
        stdin: bool,
        stdout: bool,
        stderr: bool,
    ) -> tuple[subprocess.Popen[bytes] | ContainerizedProcess, int | None]:
        return self.start_process(
            container,
            command,
            tty=tty,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )

    def start_container_process_async(self, container: dict[str, Any]) -> None:
        condition = self.container_start_condition(container)
        with condition:
            process = container.get("process")
            if process is not None and process.poll() is None:
                return
            if container.get("start_status") == "starting":
                return
            container["stop_requested"] = False
            container["start_status"] = "starting"
            container["start_error"] = ""
            thread = threading.Thread(
                target=self._start_container_process,
                args=(container,),
                name=f"pnfroot-start-{container['id'][:12]}",
                daemon=True,
            )
            container["start_thread"] = thread
            thread.start()

    def _start_container_process(self, container: dict[str, Any]) -> None:
        condition = self.container_start_condition(container)
        try:
            log_dir = Path("/tmp/pnfroot")
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = str(log_dir / f"{container['id']}.log")
            process, _ = self.start_process(
                container,
                self.build_command(container),
                stdout=True,
                stderr=True,
            )
            if container.get("stop_requested"):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                with condition:
                    container["state"] = api_pb2.CONTAINER_EXITED
                    container["finished_at"] = container["finished_at"] or int(time.time() * 1_000_000_000)
                    container["start_status"] = "stopped"
                    condition.notify_all()
                self.save_runtime_state()
                return

            container["process"] = process
            container["log_path"] = log_path
            threading.Thread(target=pipe_to_cri_log, args=(process.stdout, log_path, "stdout"), daemon=True).start()
            threading.Thread(target=pipe_to_cri_log, args=(process.stderr, log_path, "stderr"), daemon=True).start()
            with condition:
                container["state"] = api_pb2.CONTAINER_RUNNING
                if container["started_at"] == 0:
                    container["started_at"] = int(time.time() * 1_000_000_000)
                container["start_status"] = "running"
                condition.notify_all()
            self.save_runtime_state()
        except BaseException as exc:
            logger.exception("Cannot start container %s", container.get("id"))
            with condition:
                container["start_error"] = str(exc)
                container["start_status"] = "error"
                container["state"] = api_pb2.CONTAINER_EXITED
                container["finished_at"] = container["finished_at"] or int(time.time() * 1_000_000_000)
                container["exit_code"] = 125
                condition.notify_all()
            self.save_runtime_state()

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
        self.save_runtime_state()
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
        self.save_runtime_state()
        return api_pb2.StopPodSandboxResponse()

    @log_rpc
    async def RemovePodSandbox(self, request, context):
        full_id = self.find_sandbox_id(request.pod_sandbox_id)
        if full_id is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "sandbox not found")
        self.sandboxes.pop(full_id, None)
        self.save_runtime_state()
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

    @log_rpc(request_log=False)
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
        image_ref = normalize_image_ref(image_name.removeprefix("docker://")) if image_name else ""

        bundle_path = self.container_store_dir / container_id
        container = {
            "id": container_id,
            "pod_sandbox_id": sandbox_id,
            "metadata": config.metadata,
            "image": config.image,
            "image_ref": image_ref,
            "command": list(config.command) if config.command else [],
            "args": list(config.args) if config.args else [],
            "working_dir": config.working_dir or None,
            "log_path": f"{container_id}.log",
            "envs": normalize_envs(config.envs),
            "state": api_pb2.CONTAINER_CREATED,
            "created_at": int(time.time() * 1_000_000_000),
            "started_at": 0,
            "finished_at": 0,
            "exit_code": 0,
            "labels": config.labels,
            "annotations": config.annotations,
            "image_id": image_ref,
            "process": None,
            "bundle_path": str(bundle_path),
            "rootfs_path": str(bundle_path / "rootfs"),
        }
        self.containers[container_id] = container
        self.save_runtime_state()
        if image_ref:
            self.prepare_container_rootfs_async(container)
        return api_pb2.CreateContainerResponse(container_id=container_id)

    @log_rpc
    async def StartContainer(self, request, context):
        container = self.find_container(request.container_id)
        if container is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "container not found")

        if container.get("process") is None or container["process"].poll() is not None:
            if container.get("rootfs_status") == "error":
                await context.abort(grpc.StatusCode.UNKNOWN, container.get("rootfs_error") or "rootfs preparation failed")
            self.start_container_process_async(container)

        container["state"] = api_pb2.CONTAINER_RUNNING
        if container["started_at"] == 0:
            container["started_at"] = int(time.time() * 1_000_000_000)
        self.save_runtime_state()
        return api_pb2.StartContainerResponse()

    @log_rpc
    async def StopContainer(self, request, context):
        cid = self.find_container_id(request.container_id)
        container = self.containers.get(cid)
        if container is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "container not found")
        container["stop_requested"] = True
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
        self.save_runtime_state()
        return api_pb2.StopContainerResponse()

    @log_rpc
    async def RemoveContainer(self, request, context):
        cid = self.find_container_id(request.container_id)
        if cid is None:
            return api_pb2.RemoveContainerResponse()
        container = self.containers.get(cid)
        if container is not None:
            container["stop_requested"] = True
            process = container.get("process")
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            bundle_path = container.get("bundle_path")
            if bundle_path:
                shutil.rmtree(bundle_path, ignore_errors=True)
        self.containers.pop(cid, None)
        self.save_runtime_state()
        return api_pb2.RemoveContainerResponse()

    @log_rpc(request_log=False)
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
        self.refresh_container_state(container)
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
        cmd = list(request.cmd)
        if not cmd:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "cmd is required")
        process = None
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        def read_pipe(pipe: Any, chunks: list[bytes]) -> None:
            try:
                while True:
                    data = pipe.read(32768)
                    if not data:
                        break
                    chunks.append(data)
            finally:
                try:
                    pipe.close()
                except OSError:
                    pass

        try:
            process, _ = self.start_process(
                container,
                cmd,
                stdout=True,
                stderr=True,
            )
            stdout_thread = threading.Thread(target=read_pipe, args=(process.stdout, stdout_chunks), daemon=True)
            stderr_thread = threading.Thread(target=read_pipe, args=(process.stderr, stderr_chunks), daemon=True)
            stdout_thread.start()
            stderr_thread.start()
            exit_code = process.wait(timeout=request.timeout if request.timeout > 0 else None)
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            return api_pb2.ExecSyncResponse(stdout=b"".join(stdout_chunks), stderr=b"".join(stderr_chunks), exit_code=exit_code)
        except subprocess.TimeoutExpired as exc:
            if process is not None and process.poll() is None:
                process.kill()
            return api_pb2.ExecSyncResponse(stdout=b"".join(stdout_chunks), stderr=b"".join(stderr_chunks) or b"timeout", exit_code=124)

    @log_rpc
    async def Exec(self, request, context):
        container = self.find_container(request.container_id)
        if container is None:
            await context.abort(grpc.StatusCode.NOT_FOUND, "container not found")
        self.refresh_container_state(container)
        if container["state"] != api_pb2.CONTAINER_RUNNING:
            await context.abort(grpc.StatusCode.FAILED_PRECONDITION, "container is not running")
        if not request.cmd:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "cmd is required")
        if not (request.stdin or request.stdout or request.stderr):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "at least one of stdin, stdout, stderr is required")
        if request.tty and request.stderr:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "stderr cannot be true when tty is true")

        url = self.stream_server.build_exec_url(
            ExecStreamRequest(
                container_id=container["id"],
                cmd=list(request.cmd),
                tty=request.tty,
                stdin=request.stdin,
                stdout=request.stdout,
                stderr=request.stderr,
                created_at=time.time(),
            )
        )
        return api_pb2.ExecResponse(url=url)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket-path", default=SOCKET_PATH)
    parser.add_argument("--image-store-dir", default=IMAGE_STORE_DIR)
    parser.add_argument("--container-store-dir", default=CONTAINER_STORE_DIR)
    parser.add_argument("--image-platform", default=IMAGE_PLATFORM)
    parser.add_argument("--stream-host", default=STREAM_HOST)
    parser.add_argument("--stream-port", type=int, default=STREAM_PORT)
    parser.add_argument(
        "--stream-public-host",
        help="host name or address embedded into CRI Exec streaming URLs",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    configure_logging(args.verbose)

    if os.path.exists(args.socket_path):
        os.remove(args.socket_path)

    server = grpc.aio.server()
    runtime_service = RuntimeService(
        image_store_dir=args.image_store_dir,
        container_store_dir=args.container_store_dir,
        image_platform=args.image_platform,
        stream_host=args.stream_host,
        stream_port=args.stream_port,
        stream_public_host=args.stream_public_host,
    )
    api_pb2_grpc.add_RuntimeServiceServicer_to_server(
        runtime_service,
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
    logger.info("Container store dir: %s", args.container_store_dir)
    logger.info("Image platform: %s", args.image_platform)
    logger.info("Streaming server: %s:%s", args.stream_host, args.stream_port)
    try:
        await server.wait_for_termination()
    finally:
        runtime_service.shutdown_stream_server()
        await server.stop(0)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
