import importlib.util
import asyncio
import base64
import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import unittest
import zlib
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pnfroot", ROOT / "pnfroot.py")
pnfroot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pnfroot)


class PnfrootTests(unittest.TestCase):
    def test_pull_image_from_existing_rootfs_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "image"
            pulled_path = pnfroot.pull_image_to_dir("ubuntu_c", output=str(output_dir))

            self.assertTrue(Path(pulled_path).exists())
            self.assertTrue((Path(pulled_path) / "etc").exists())

    def test_image_service_loads_existing_rootfs_directory_without_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            image_dir = Path(tmpdir) / "busybox_latest"
            create_minimal_rootfs(image_dir)

            service = pnfroot.ImageService(image_store_dir=tmpdir)
            response = asyncio.run(service.ListImages(pnfroot.api_pb2.ListImagesRequest(), FakeContext()))

            repo_tags = [tag for image in response.images for tag in image.repo_tags]
            self.assertIn("busybox:latest", repo_tags)
            self.assertTrue((image_dir / pnfroot.IMAGE_METADATA_FILE).exists())
            self.assertTrue((image_dir / "blobs" / "sha256").exists())
            self.assertFalse((image_dir / "etc").exists())

    def test_pull_image_writes_blobs_not_unpacked_rootfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source_rootfs = Path(tmpdir) / "source-rootfs"
            image_store = Path(tmpdir) / "images"
            create_minimal_rootfs(source_rootfs)
            service = pnfroot.ImageService(image_store_dir=image_store)

            image_ref = asyncio.run(
                service.PullImage(
                    pnfroot.api_pb2.PullImageRequest(image=pnfroot.api_pb2.ImageSpec(image=str(source_rootfs))),
                    FakeContext(),
                )
            ).image_ref

            image_dir = image_store / pnfroot.image_dir_name(image_ref)
            self.assertTrue((image_dir / "blobs" / "sha256").exists())
            self.assertFalse((image_dir / "etc").exists())

    def test_unknown_image_does_not_fallback_to_ubuntu_rootfs(self) -> None:
        with self.assertRaises(FileNotFoundError):
            pnfroot.resolve_local_image_source("definitely-missing-pnfroot-image")

    def test_runtime_refreshes_legacy_registry_cache(self) -> None:
        image_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-images-")
        container_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-containers-")
        self.addCleanup(image_store.cleanup)
        self.addCleanup(container_store.cleanup)

        image_ref = "registry.example.invalid/library/fallbacktest:latest"
        image_path = Path(image_store.name) / pnfroot.image_dir_name(image_ref)
        image_path.mkdir(parents=True)
        (image_path / "ubuntu-marker").write_text("stale fallback rootfs\n", encoding="utf-8")
        stale = pnfroot.image_metadata(image_ref, image_path)
        stale.update(
            {
                "image_id": "sha256:" + "1" * 64,
                "layer_digests": ["sha256:" + "2" * 64],
            }
        )
        pnfroot.write_image_metadata(stale)

        calls = []
        original_pull = pnfroot.pull_image_to_store

        def fake_pull(image, image_store_dir, platform=pnfroot.IMAGE_PLATFORM):
            calls.append(image)
            refreshed_path = Path(image_store_dir) / pnfroot.image_dir_name(image_ref)
            refreshed_path.mkdir(parents=True, exist_ok=True)
            img = pnfroot.image_metadata(image_ref, refreshed_path)
            img.update(
                {
                    "image_id": "sha256:" + "3" * 64,
                    "layer_digests": ["sha256:" + "4" * 64],
                    "source_type": "registry",
                    "source_image": image,
                }
            )
            pnfroot.write_image_metadata(img)
            return img

        pnfroot.pull_image_to_store = fake_pull
        try:
            runtime = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)
            self.assertEqual(runtime.ensure_image_pulled(image_ref, image_ref), image_path)
        finally:
            pnfroot.pull_image_to_store = original_pull

        self.assertEqual(calls, [image_ref])
        self.assertFalse((image_path / "ubuntu-marker").exists())

    def test_unpack_image_handles_absolute_symlink_and_rebuilds_partial_rootfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            source_rootfs = base / "source-rootfs"
            image_store = base / "images"
            container_store = base / "containers"
            create_minimal_rootfs(source_rootfs)
            (source_rootfs / "usr" / "bin").mkdir(parents=True)
            (source_rootfs / "usr" / "bin" / "awk").write_text("#!/bin/sh\n", encoding="utf-8")
            os.symlink("/usr/bin/awk", source_rootfs / "etc" / "absolute-awk")
            img = pnfroot.pull_image_to_store(str(source_rootfs), image_store)

            runtime = pnfroot.RuntimeService(image_store_dir=image_store, container_store_dir=container_store)
            container = {
                "id": "container-partial",
                "image": pnfroot.api_pb2.ImageSpec(image=str(source_rootfs)),
                "image_ref": img["id"],
                "envs": {},
                "working_dir": None,
                "bundle_path": str(container_store / "container-partial"),
                "rootfs_path": str(container_store / "container-partial" / "rootfs"),
            }
            rootfs = Path(container["rootfs_path"])
            (rootfs / "etc").mkdir(parents=True)
            (rootfs / "etc" / "partial").write_text("broken\n", encoding="utf-8")

            runtime.ensure_container_rootfs(container)

            self.assertFalse((rootfs / "etc" / "partial").exists())
            self.assertTrue((rootfs / "usr" / "bin" / "awk").exists())
            self.assertTrue((rootfs / "etc" / "absolute-awk").is_symlink())
            self.assertEqual(os.readlink(rootfs / "etc" / "absolute-awk"), "/usr/bin/awk")
            self.assertTrue((container_store / "container-partial" / pnfroot.ROOTFS_METADATA_FILE).exists())

    def test_exec_returns_streaming_url_and_proxies_output(self) -> None:
        runtime, process = self._runtime_with_running_container("container-output")
        try:
            response = asyncio.run(
                runtime.Exec(
                    pnfroot.api_pb2.ExecRequest(
                        container_id="container-output",
                        cmd=["/bin/sh", "-c", "printf out; printf err >&2"],
                        stdout=True,
                        stderr=True,
                    ),
                    FakeContext(),
                )
            )

            with websocket_connect(response.url) as sock:
                messages = read_until_status(sock)

            stdout = b"".join(data for channel, data in messages if channel == pnfroot.STREAM_STDOUT)
            stderr = b"".join(data for channel, data in messages if channel == pnfroot.STREAM_STDERR)
            statuses = [json.loads(data.decode("utf-8")) for channel, data in messages if channel == pnfroot.STREAM_ERROR and data]

            self.assertEqual(stdout, b"out")
            self.assertEqual(stderr, b"err")
            self.assertEqual(statuses[-1]["status"], "Success")
        finally:
            process.terminate()
            process.wait(timeout=5)
            runtime.shutdown_stream_server()

    def test_exec_proxies_stdin(self) -> None:
        runtime, process = self._runtime_with_running_container("container-stdin")
        try:
            url = runtime.stream_server.build_exec_url(
                pnfroot.ExecStreamRequest(
                    container_id="container-stdin",
                    cmd=["/bin/sh", "-c", "cat"],
                    tty=False,
                    stdin=True,
                    stdout=True,
                    stderr=False,
                    created_at=pnfroot.time.time(),
                )
            )

            with websocket_connect(url) as sock:
                read_ws_frame(sock)
                send_ws_channel(sock, pnfroot.STREAM_STDIN, b"hello\n")
                send_ws_channel(sock, pnfroot.STREAM_CLOSE, bytes([pnfroot.STREAM_STDIN]))
                messages = read_until_status(sock)

            stdout = b"".join(data for channel, data in messages if channel == pnfroot.STREAM_STDOUT)
            statuses = [json.loads(data.decode("utf-8")) for channel, data in messages if channel == pnfroot.STREAM_ERROR and data]

            self.assertEqual(stdout, b"hello\n")
            self.assertEqual(statuses[-1]["status"], "Success")
        finally:
            process.terminate()
            process.wait(timeout=5)
            runtime.shutdown_stream_server()

    def test_exec_supports_spdy_transport(self) -> None:
        runtime, process = self._runtime_with_running_container("container-spdy")
        try:
            response = asyncio.run(
                runtime.Exec(
                    pnfroot.api_pb2.ExecRequest(
                        container_id="container-spdy",
                        cmd=["/bin/sh", "-c", "printf spdy-out; printf spdy-err >&2"],
                        stdout=True,
                        stderr=True,
                    ),
                    FakeContext(),
                )
            )

            with spdy_connect(response.url) as client:
                client.create_stream("error")
                client.create_stream("stdout")
                client.create_stream("stderr")
                messages = client.read_until_status()

            stdout = b"".join(data for stream_type, data in messages if stream_type == "stdout")
            stderr = b"".join(data for stream_type, data in messages if stream_type == "stderr")
            statuses = [json.loads(data.decode("utf-8")) for stream_type, data in messages if stream_type == "error" and data]

            self.assertEqual(stdout, b"spdy-out")
            self.assertEqual(stderr, b"spdy-err")
            self.assertEqual(statuses[-1]["status"], "Success")
        finally:
            process.terminate()
            process.wait(timeout=5)
            runtime.shutdown_stream_server()

    def test_execsync_uses_ptrace_rootfs_without_subprocess_popen(self) -> None:
        runtime = self._runtime_with_rootfs_container("container-rootfs")
        original_popen = pnfroot.subprocess.Popen
        pnfroot.subprocess.Popen = self._fail_popen
        try:
            response = asyncio.run(
                runtime.ExecSync(
                    pnfroot.api_pb2.ExecSyncRequest(
                        container_id="container-rootfs",
                        cmd=["/bin/sh", "-c", "cat /.rock/metadata.yaml"],
                        timeout=5,
                    ),
                    FakeContext(),
                )
            )
        finally:
            pnfroot.subprocess.Popen = original_popen
            runtime.shutdown_stream_server()

        self.assertEqual(response.exit_code, 0, response.stderr)
        self.assertIn(b"name: ubuntu", response.stdout)

    def test_create_container_unpacks_rootfs_outside_image_store_without_pull(self) -> None:
        image_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-images-")
        container_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-containers-")
        source_dir = tempfile.TemporaryDirectory(prefix="pnfroot-test-source-")
        self.addCleanup(image_store.cleanup)
        self.addCleanup(container_store.cleanup)
        self.addCleanup(source_dir.cleanup)
        source_rootfs = Path(source_dir.name) / "rootfs"
        create_minimal_rootfs(source_rootfs)
        runtime = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)

        pod_response = asyncio.run(
            runtime.RunPodSandbox(
                pnfroot.api_pb2.RunPodSandboxRequest(
                    config=pnfroot.api_pb2.PodSandboxConfig(
                        metadata=pnfroot.api_pb2.PodSandboxMetadata(name="pod", uid="uid", namespace="default", attempt=1),
                    )
                ),
                FakeContext(),
            )
        )
        response = asyncio.run(
            runtime.CreateContainer(
                pnfroot.api_pb2.CreateContainerRequest(
                    pod_sandbox_id=pod_response.pod_sandbox_id,
                    config=pnfroot.api_pb2.ContainerConfig(
                        metadata=pnfroot.api_pb2.ContainerMetadata(name="busybox", attempt=1),
                        image=pnfroot.api_pb2.ImageSpec(image=str(source_rootfs)),
                        command=["/bin/sh"],
                    ),
                    sandbox_config=pnfroot.api_pb2.PodSandboxConfig(),
                ),
                FakeContext(),
            )
        )

        container = runtime.find_container(response.container_id)
        self.assertIsNotNone(container)
        runtime.wait_for_container_rootfs(container)
        image_path = runtime.image_path(container["image_ref"])
        rootfs_path = runtime.container_rootfs_path(container)
        self.assertTrue((image_path / "blobs" / "sha256").exists())
        self.assertFalse((image_path / "etc").exists())
        self.assertTrue((rootfs_path / "etc" / "fixture-release").exists())

        image_service = pnfroot.ImageService(image_store_dir=image_store.name)
        images = asyncio.run(image_service.ListImages(pnfroot.api_pb2.ListImagesRequest(), FakeContext())).images
        repo_tags = [tag for image in images for tag in image.repo_tags]
        self.assertIn(container["image_ref"], repo_tags)

    def test_create_container_does_not_wait_for_rootfs_prepare(self) -> None:
        image_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-images-")
        container_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-containers-")
        self.addCleanup(image_store.cleanup)
        self.addCleanup(container_store.cleanup)
        runtime = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)
        started = threading.Event()
        release = threading.Event()

        def slow_prepare(container):
            started.set()
            release.wait(timeout=5)
            condition = runtime.container_rootfs_condition(container)
            with condition:
                container["rootfs_status"] = "fallback"
                condition.notify_all()

        runtime._prepare_container_rootfs = slow_prepare
        pod_response = asyncio.run(
            runtime.RunPodSandbox(
                pnfroot.api_pb2.RunPodSandboxRequest(
                    config=pnfroot.api_pb2.PodSandboxConfig(
                        metadata=pnfroot.api_pb2.PodSandboxMetadata(name="pod", uid="uid", namespace="default", attempt=1),
                    )
                ),
                FakeContext(),
            )
        )

        before = pnfroot.time.monotonic()
        response = asyncio.run(
            runtime.CreateContainer(
                pnfroot.api_pb2.CreateContainerRequest(
                    pod_sandbox_id=pod_response.pod_sandbox_id,
                    config=pnfroot.api_pb2.ContainerConfig(
                        metadata=pnfroot.api_pb2.ContainerMetadata(name="busybox", attempt=1),
                        image=pnfroot.api_pb2.ImageSpec(image="busybox"),
                    ),
                    sandbox_config=pnfroot.api_pb2.PodSandboxConfig(),
                ),
                FakeContext(),
            )
        )
        elapsed = pnfroot.time.monotonic() - before
        release.set()

        self.assertTrue(response.container_id)
        self.assertLess(elapsed, 1)
        self.assertTrue(started.wait(timeout=1))

    def test_runtime_persists_pods_and_containers_across_restart(self) -> None:
        image_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-images-")
        container_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-containers-")
        self.addCleanup(image_store.cleanup)
        self.addCleanup(container_store.cleanup)
        runtime = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)

        pod_response = asyncio.run(
            runtime.RunPodSandbox(
                pnfroot.api_pb2.RunPodSandboxRequest(
                    config=pnfroot.api_pb2.PodSandboxConfig(
                        metadata=pnfroot.api_pb2.PodSandboxMetadata(name="persist-pod", uid="uid", namespace="default", attempt=1),
                        labels={"pod-label": "yes"},
                    ),
                    runtime_handler="runc-ish",
                ),
                FakeContext(),
            )
        )
        container_response = asyncio.run(
            runtime.CreateContainer(
                pnfroot.api_pb2.CreateContainerRequest(
                    pod_sandbox_id=pod_response.pod_sandbox_id,
                    config=pnfroot.api_pb2.ContainerConfig(
                        metadata=pnfroot.api_pb2.ContainerMetadata(name="persist-container", attempt=2),
                        image=pnfroot.api_pb2.ImageSpec(image=""),
                        command=["/bin/sh"],
                        args=["-c", "true"],
                        labels={"container-label": "yes"},
                    ),
                    sandbox_config=pnfroot.api_pb2.PodSandboxConfig(),
                ),
                FakeContext(),
            )
        )

        restored = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)
        pods = asyncio.run(restored.ListPodSandbox(pnfroot.api_pb2.ListPodSandboxRequest(), FakeContext())).items
        containers = asyncio.run(restored.ListContainers(pnfroot.api_pb2.ListContainersRequest(), FakeContext())).containers

        self.assertEqual([pod.id for pod in pods], [pod_response.pod_sandbox_id])
        self.assertEqual(pods[0].metadata.name, "persist-pod")
        self.assertEqual(pods[0].labels["pod-label"], "yes")
        self.assertEqual([container.id for container in containers], [container_response.container_id])
        self.assertEqual(containers[0].metadata.name, "persist-container")
        self.assertEqual(containers[0].metadata.attempt, 2)
        self.assertEqual(containers[0].labels["container-label"], "yes")
        self.assertEqual(containers[0].state, pnfroot.api_pb2.CONTAINER_CREATED)

    def test_running_container_is_loaded_as_exited_after_restart(self) -> None:
        image_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-images-")
        container_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-containers-")
        self.addCleanup(image_store.cleanup)
        self.addCleanup(container_store.cleanup)
        runtime = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)

        pod_response = asyncio.run(
            runtime.RunPodSandbox(
                pnfroot.api_pb2.RunPodSandboxRequest(
                    config=pnfroot.api_pb2.PodSandboxConfig(
                        metadata=pnfroot.api_pb2.PodSandboxMetadata(name="pod", uid="uid", namespace="default", attempt=1),
                    )
                ),
                FakeContext(),
            )
        )
        container_response = asyncio.run(
            runtime.CreateContainer(
                pnfroot.api_pb2.CreateContainerRequest(
                    pod_sandbox_id=pod_response.pod_sandbox_id,
                    config=pnfroot.api_pb2.ContainerConfig(
                        metadata=pnfroot.api_pb2.ContainerMetadata(name="container", attempt=1),
                        image=pnfroot.api_pb2.ImageSpec(image=""),
                    ),
                    sandbox_config=pnfroot.api_pb2.PodSandboxConfig(),
                ),
                FakeContext(),
            )
        )
        container = runtime.find_container(container_response.container_id)
        container["state"] = pnfroot.api_pb2.CONTAINER_RUNNING
        container["started_at"] = 123
        runtime.save_runtime_state()

        restored = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)
        restored_container = restored.find_container(container_response.container_id)
        self.assertEqual(restored_container["state"], pnfroot.api_pb2.CONTAINER_EXITED)
        self.assertGreater(restored_container["finished_at"], 0)
        self.assertIsNone(restored_container["process"])

    def test_container_env_does_not_inherit_host_prompt(self) -> None:
        runtime = self._runtime_with_rootfs_container("container-env")
        original_ps1 = os.environ.get("PS1")
        os.environ["PS1"] = r"\[\](.venv) noisy-host$ \[\]"
        try:
            env = runtime.container_env(runtime.find_container("container-env"))
        finally:
            if original_ps1 is None:
                os.environ.pop("PS1", None)
            else:
                os.environ["PS1"] = original_ps1
            runtime.shutdown_stream_server()

        self.assertNotIn("PS1", env)
        self.assertEqual(env["HOME"], "/root")

    def _runtime_with_running_container(self, container_id: str):
        image_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-images-")
        container_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-containers-")
        self.addCleanup(image_store.cleanup)
        self.addCleanup(container_store.cleanup)
        runtime = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)
        process = subprocess.Popen(["sleep", "30"])
        runtime.containers[container_id] = {
            "id": container_id,
            "pod_sandbox_id": "pod",
            "metadata": pnfroot.api_pb2.ContainerMetadata(name=container_id),
            "image": pnfroot.api_pb2.ImageSpec(),
            "image_ref": "",
            "command": [],
            "args": [],
            "working_dir": None,
            "log_path": f"{container_id}.log",
            "envs": {},
            "state": pnfroot.api_pb2.CONTAINER_RUNNING,
            "created_at": 0,
            "started_at": 1,
            "finished_at": 0,
            "exit_code": 0,
            "labels": {},
            "annotations": {},
            "image_id": "",
            "process": process,
        }
        return runtime, process

    def _runtime_with_rootfs_container(self, container_id: str):
        image_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-images-")
        container_store = tempfile.TemporaryDirectory(prefix="pnfroot-test-containers-")
        self.addCleanup(image_store.cleanup)
        self.addCleanup(container_store.cleanup)
        runtime = pnfroot.RuntimeService(image_store_dir=image_store.name, container_store_dir=container_store.name)
        image_ref = "ubuntu_c:latest"
        bundle_path = Path(container_store.name) / container_id
        rootfs_path = bundle_path / "rootfs"
        pnfroot.pull_image_to_dir(
            "ubuntu_c",
            output=str(rootfs_path),
        )
        runtime.containers[container_id] = {
            "id": container_id,
            "pod_sandbox_id": "pod",
            "metadata": pnfroot.api_pb2.ContainerMetadata(name=container_id),
            "image": pnfroot.api_pb2.ImageSpec(image=image_ref),
            "image_ref": image_ref,
            "command": [],
            "args": [],
            "working_dir": None,
            "log_path": f"{container_id}.log",
            "envs": {},
            "state": pnfroot.api_pb2.CONTAINER_RUNNING,
            "created_at": 0,
            "started_at": 1,
            "finished_at": 0,
            "exit_code": 0,
            "labels": {},
            "annotations": {},
            "image_id": image_ref,
            "process": None,
            "bundle_path": str(bundle_path),
            "rootfs_path": str(rootfs_path),
            "rootfs_status": "ready",
        }
        return runtime

    def _fail_popen(self, *args, **kwargs):
        raise AssertionError("subprocess.Popen must not be used for rootfs containers")


class FakeContext:
    async def abort(self, code, message):
        raise AssertionError(f"unexpected abort {code}: {message}")


def create_minimal_rootfs(rootfs: Path) -> None:
    (rootfs / "etc").mkdir(parents=True, exist_ok=True)
    (rootfs / "bin").mkdir(parents=True, exist_ok=True)
    (rootfs / "etc" / "fixture-release").write_text("pnfroot-test\n", encoding="utf-8")
    (rootfs / "bin" / "fixture").write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(rootfs / "bin" / "fixture", 0o755)


class SpdyTestClient:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.next_stream_id = 1
        self.streams_by_id: dict[int, str] = {}
        self.compressor = zlib.compressobj(
            level=zlib.Z_BEST_COMPRESSION,
            wbits=zlib.MAX_WBITS,
            zdict=pnfroot.SPDY_HEADER_DICTIONARY,
        )
        self.decompressor = zlib.decompressobj(
            wbits=zlib.MAX_WBITS,
            zdict=pnfroot.SPDY_HEADER_DICTIONARY,
        )

    def __enter__(self) -> "SpdyTestClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def create_stream(self, stream_type: str) -> int:
        stream_id = self.next_stream_id
        self.next_stream_id += 2
        headers = self.header_block({"streamType": stream_type})
        payload = struct.pack("!IIBB", stream_id, 0, 0, 0) + headers
        self.write_control_frame(pnfroot.SPDY_TYPE_SYN_STREAM, 0, payload)
        self.streams_by_id[stream_id] = stream_type
        while True:
            frame = self.read_frame()
            if frame["type"] == "syn_reply" and frame["stream_id"] == stream_id:
                return stream_id

    def read_until_status(self) -> list[tuple[str, bytes]]:
        messages = []
        while True:
            frame = self.read_frame()
            if frame["type"] != "data":
                continue
            stream_type = self.streams_by_id.get(frame["stream_id"], "")
            data = frame["data"]
            if data:
                messages.append((stream_type, data))
            if stream_type == "error" and data:
                break
        return messages

    def header_block(self, headers: dict[str, str]) -> bytes:
        raw = bytearray()
        raw.extend(struct.pack("!I", len(headers)))
        for name, value in headers.items():
            name_bytes = name.lower().encode("utf-8")
            value_bytes = value.encode("utf-8")
            raw.extend(struct.pack("!I", len(name_bytes)))
            raw.extend(name_bytes)
            raw.extend(struct.pack("!I", len(value_bytes)))
            raw.extend(value_bytes)
        return self.compressor.compress(bytes(raw)) + self.compressor.flush(zlib.Z_SYNC_FLUSH)

    def write_control_frame(self, frame_type: int, flags: int, payload: bytes) -> None:
        header = struct.pack(
            "!HHI",
            0x8000 | pnfroot.SPDY_VERSION,
            frame_type,
            ((flags & 0xFF) << 24) | len(payload),
        )
        self.sock.sendall(header + payload)

    def read_frame(self) -> dict[str, object]:
        first_word = struct.unpack("!I", recv_exact(self.sock, 4))[0]
        flags_and_length = struct.unpack("!I", recv_exact(self.sock, 4))[0]
        flags = (flags_and_length >> 24) & 0xFF
        length = flags_and_length & 0xFFFFFF
        payload = recv_exact(self.sock, length) if length else b""
        if first_word & 0x80000000:
            frame_type = first_word & 0xFFFF
            if frame_type == pnfroot.SPDY_TYPE_SYN_REPLY:
                stream_id = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
                self.decompressor.decompress(payload[4:])
                return {"type": "syn_reply", "stream_id": stream_id}
            if frame_type == pnfroot.SPDY_TYPE_GOAWAY:
                return {"type": "goaway"}
            return {"type": "control", "frame_type": frame_type}
        return {
            "type": "data",
            "stream_id": first_word & 0x7FFFFFFF,
            "flags": flags,
            "data": payload,
        }

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def spdy_connect(url: str) -> SpdyTestClient:
    parsed = urlsplit(url)
    sock = socket.create_connection((parsed.hostname, parsed.port), timeout=5)
    request = (
        f"GET {parsed.path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}:{parsed.port}\r\n"
        "Upgrade: SPDY/3.1\r\n"
        "Connection: Upgrade\r\n"
        "X-Stream-Protocol-Version: v5.channel.k8s.io\r\n"
        "X-Stream-Protocol-Version: v4.channel.k8s.io\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = b""
    while b"\r\n\r\n" not in response:
        response += sock.recv(4096)
    if b" 101 " not in response.split(b"\r\n", 1)[0]:
        raise AssertionError(response.decode("latin1"))
    return SpdyTestClient(sock)


def websocket_connect(url: str) -> socket.socket:
    parsed = urlsplit(url)
    sock = socket.create_connection((parsed.hostname, parsed.port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {parsed.path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}:{parsed.port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: v5.channel.k8s.io\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = b""
    while b"\r\n\r\n" not in response:
        response += sock.recv(4096)
    if b" 101 " not in response.split(b"\r\n", 1)[0]:
        raise AssertionError(response.decode("latin1"))
    return sock


def send_ws_channel(sock: socket.socket, channel: int, data: bytes) -> None:
    payload = bytes([channel]) + data
    mask = b"test"
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    header = bytearray([0x82])
    if len(payload) < 126:
        header.append(0x80 | len(payload))
    elif len(payload) <= 0xFFFF:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", len(payload)))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", len(payload)))
    sock.sendall(bytes(header) + mask + masked)


def read_ws_frame(sock: socket.socket) -> tuple[int, bytes]:
    first, second = recv_exact(sock, 2)
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    return opcode, recv_exact(sock, length) if length else b""


def read_until_status(sock: socket.socket) -> list[tuple[int, bytes]]:
    messages = []
    while True:
        opcode, payload = read_ws_frame(sock)
        if opcode == 0x8:
            break
        if opcode == 0x9:
            continue
        if opcode != 0x2 or not payload:
            continue
        channel, data = payload[0], payload[1:]
        messages.append((channel, data))
        if channel == pnfroot.STREAM_ERROR and data:
            break
    return messages


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("socket closed")
        data.extend(chunk)
    return bytes(data)


if __name__ == "__main__":
    unittest.main()
