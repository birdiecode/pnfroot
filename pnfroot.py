#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import asyncio
import base64
import binascii
import fcntl
import hashlib
import http.server
import json
import os
import queue
import re
import signal
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import termios
import threading
import time
import tempfile
import uuid
import warnings
import zlib
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
EXAMPLE_DIR = ROOT / "example"
if str(EXAMPLE_DIR) not in sys.path:
    sys.path.insert(0, str(EXAMPLE_DIR))

import grpc

from cri_common import configure_logging, labels_match, log_rpc, logger, normalize_image_ref
import ptrace_syscalls
import tools.api_pb2 as api_pb2
import tools.api_pb2_grpc as api_pb2_grpc


SOCKET_PATH = "/tmp/pnfroot.sock"
IMAGE_STORE_DIR = "/tmp/pnfroot/images"
CONTAINER_STORE_DIR = "/tmp/pnfroot/containers"
IMAGE_PLATFORM = "linux/amd64"
DEFAULT_IMAGE_SIZE = 1
IMAGE_METADATA_FILE = "pnfroot-image.json"
ROOTFS_METADATA_FILE = "pnfroot-rootfs.json"
RUNTIME_STATE_FILE = "pnfroot-runtime-state.json"
STREAM_HOST = "127.0.0.1"
STREAM_PORT = 0
STREAM_TOKEN_TTL_SECONDS = 300
WEBSOCKET_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
CHANNEL_PROTOCOLS = (
    "v5.channel.k8s.io",
    "v4.channel.k8s.io",
    "v3.channel.k8s.io",
    "v2.channel.k8s.io",
    "channel.k8s.io",
)
WEBSOCKET_PROTOCOLS = (
    "v5.channel.k8s.io",
    "v4.channel.k8s.io",
    "v3.channel.k8s.io",
    "v2.channel.k8s.io",
    "channel.k8s.io",
    "v4.base64.channel.k8s.io",
    "v3.base64.channel.k8s.io",
    "v2.base64.channel.k8s.io",
    "base64.channel.k8s.io",
)
STREAM_STDIN = 0
STREAM_STDOUT = 1
STREAM_STDERR = 2
STREAM_ERROR = 3
STREAM_RESIZE = 4
STREAM_CLOSE = 255
SPDY_UPGRADE = "SPDY/3.1"
SPDY_VERSION = 3
SPDY_TYPE_SYN_STREAM = 0x0001
SPDY_TYPE_SYN_REPLY = 0x0002
SPDY_TYPE_RST_STREAM = 0x0003
SPDY_TYPE_SETTINGS = 0x0004
SPDY_TYPE_PING = 0x0006
SPDY_TYPE_GOAWAY = 0x0007
SPDY_TYPE_HEADERS = 0x0008
SPDY_TYPE_WINDOW_UPDATE = 0x0009
SPDY_FLAG_FIN = 0x01
SPDY_STATUS_CANCEL = 5
SPDY_HEADER_DICTIONARY = base64.b64decode(
    b"AAAAB29wdGlvbnMAAAAEaGVhZAAAAARwb3N0AAAAA3B1dAAAAAZkZWxldGUAAAAFdHJhY2UAAAAG"
    b"YWNjZXB0AAAADmFjY2VwdC1jaGFyc2V0AAAAD2FjY2VwdC1lbmNvZGluZwAAAA9hY2NlcHQtbGFu"
    b"Z3VhZ2UAAAANYWNjZXB0LXJhbmdlcwAAAANhZ2UAAAAFYWxsb3cAAAANYXV0aG9yaXphdGlvbgAA"
    b"AA1jYWNoZS1jb250cm9sAAAACmNvbm5lY3Rpb24AAAAMY29udGVudC1iYXNlAAAAEGNvbnRlbnQt"
    b"ZW5jb2RpbmcAAAAQY29udGVudC1sYW5ndWFnZQAAAA5jb250ZW50LWxlbmd0aAAAABBjb250ZW50"
    b"LWxvY2F0aW9uAAAAC2NvbnRlbnQtbWQ1AAAADWNvbnRlbnQtcmFuZ2UAAAAMY29udGVudC10eXBl"
    b"AAAABGRhdGUAAAAEZXRhZwAAAAZleHBlY3QAAAAHZXhwaXJlcwAAAARmcm9tAAAABGhvc3QAAAAI"
    b"aWYtbWF0Y2gAAAARaWYtbW9kaWZpZWQtc2luY2UAAAANaWYtbm9uZS1tYXRjaAAAAAhpZi1yYW5n"
    b"ZQAAABNpZi11bm1vZGlmaWVkLXNpbmNlAAAADWxhc3QtbW9kaWZpZWQAAAAIbG9jYXRpb24AAAAM"
    b"bWF4LWZvcndhcmRzAAAABnByYWdtYQAAABJwcm94eS1hdXRoZW50aWNhdGUAAAATcHJveHktYXV0"
    b"aG9yaXphdGlvbgAAAAVyYW5nZQAAAAdyZWZlcmVyAAAAC3JldHJ5LWFmdGVyAAAABnNlcnZlcgAA"
    b"AAJ0ZQAAAAd0cmFpbGVyAAAAEXRyYW5zZmVyLWVuY29kaW5nAAAAB3VwZ3JhZGUAAAAKdXNlci1h"
    b"Z2VudAAAAAR2YXJ5AAAAA3ZpYQAAAAd3YXJuaW5nAAAAEHd3dy1hdXRoZW50aWNhdGUAAAAGbWV0"
    b"aG9kAAAAA2dldAAAAAZzdGF0dXMAAAAGMjAwIE9LAAAAB3ZlcnNpb24AAAAISFRUUC8xLjEAAAAD"
    b"dXJsAAAABnB1YmxpYwAAAApzZXQtY29va2llAAAACmtlZXAtYWxpdmUAAAAGb3JpZ2luMTAwMTAx"
    b"MjAxMjAyMjA1MjA2MzAwMzAyMzAzMzA0MzA1MzA2MzA3NDAyNDA1NDA2NDA3NDA4NDA5NDEwNDEx"
    b"NDEyNDEzNDE0NDE1NDE2NDE3NTAyNTA0NTA1MjAzIE5vbi1BdXRob3JpdGF0aXZlIEluZm9ybWF0"
    b"aW9uMjA0IE5vIENvbnRlbnQzMDEgTW92ZWQgUGVybWFuZW50bHk0MDAgQmFkIFJlcXVlc3Q0MDEg"
    b"VW5hdXRob3JpemVkNDAzIEZvcmJpZGRlbjQwNCBOb3QgRm91bmQ1MDAgSW50ZXJuYWwgU2VydmVy"
    b"IEVycm9yNTAxIE5vdCBJbXBsZW1lbnRlZDUwMyBTZXJ2aWNlIFVuYXZhaWxhYmxlSmFuIEZlYiBN"
    b"YXIgQXByIE1heSBKdW4gSnVsIEF1ZyBTZXB0IE9jdCBOb3YgRGVjIDAwOjAwOjAwIE1vbiwgVHVl"
    b"LCBXZWQsIFRodSwgRnJpLCBTYXQsIFN1biwgR01UY2h1bmtlZCx0ZXh0L2h0bWwsaW1hZ2UvcG5n"
    b"LGltYWdlL2pwZyxpbWFnZS9naWYsYXBwbGljYXRpb24veG1sLGFwcGxpY2F0aW9uL3hodG1sK3ht"
    b"bCx0ZXh0L3BsYWluLHRleHQvamF2YXNjcmlwdCxwdWJsaWNwcml2YXRlbWF4LWFnZT1nemlwLGRl"
    b"ZmxhdGUsc2RjaGNoYXJzZXQ9dXRmLThjaGFyc2V0PWlzby04ODU5LTEsdXRmLSwqLGVucT0wLg=="
)
REGISTRY_MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
REGISTRY_LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}


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


def path_size(path: Path) -> int:
    total = 0
    for item in path.rglob("*"):
        if item.is_file():
            total += item.stat().st_size
    return total or DEFAULT_IMAGE_SIZE


def image_metadata(image_ref: str, image_path: Path) -> dict[str, Any]:
    return {
        "id": image_ref,
        "image_id": image_ref,
        "repo_tags": [image_ref],
        "size": path_size(image_path),
        "path": str(image_path),
    }


def infer_image_ref_from_dir_name(name: str) -> str:
    if name.endswith("_latest") and len(name) > len("_latest"):
        return f"{name[:-len('_latest')]}:latest"
    return name


def write_image_metadata(img: dict[str, Any]) -> None:
    metadata_path = Path(img["path"]) / IMAGE_METADATA_FILE
    with open(metadata_path, "w", encoding="utf-8") as handle:
        json.dump(img, handle, indent=2, sort_keys=True)
        handle.write("\n")


def read_image_metadata(image_path: Path) -> dict[str, Any] | None:
    metadata_path = image_path / IMAGE_METADATA_FILE
    if not metadata_path.exists():
        return None
    try:
        with open(metadata_path, "r", encoding="utf-8") as handle:
            data = handle.read()
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            legacy = ast.literal_eval(data)
            return legacy if isinstance(legacy, dict) else None
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.warning("Cannot read image metadata %s: %s", metadata_path, exc)
        return None


def encode_proto(message: Any | None) -> str:
    if message is None:
        return ""
    return base64.b64encode(message.SerializeToString()).decode("ascii")


def decode_proto(message_cls: Any, payload: str | None) -> Any:
    message = message_cls()
    if payload:
        message.ParseFromString(base64.b64decode(payload.encode("ascii")))
    return message


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


def image_dir_name(image_ref: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", image_ref).strip("_")
    return name or "image"


def is_local_image_reference(image: str) -> bool:
    if not image:
        return False
    expanded = os.path.expanduser(image)
    return (
        expanded.startswith("/")
        or expanded.startswith("./")
        or expanded.startswith("../")
        or image.startswith("file://")
    )


def local_image_source_exists(image: str) -> bool:
    try:
        resolve_local_image_source(image)
    except FileNotFoundError:
        return False
    return True


def resolve_local_image_source(image: str) -> Path:
    aliases = []
    if image:
        if image.startswith("file://"):
            aliases.append(urlsplit(image).path)
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
        if candidate.exists():
            return candidate

    raise FileNotFoundError(f"cannot resolve image {image!r} from local filesystem")


def pull_image_to_dir(image: str, output: str, platform: str = IMAGE_PLATFORM) -> str:
    """Unpack a local image fixture into a rootfs directory."""

    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    source = resolve_local_image_source(image)
    if source.is_dir():
        _copy_tree_safe(source, output_path)
        return str(output_path)
    if source.is_file():
        shutil.copy2(source, output_path / source.name)
        return str(output_path)
    raise FileNotFoundError(f"cannot resolve image {image!r} from local filesystem")


def blob_path(image_path: Path, digest: str) -> Path:
    algorithm, hex_digest = digest.split(":", 1)
    return image_path / "blobs" / algorithm / hex_digest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def sha256_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def write_blob_bytes(image_path: Path, payload: bytes) -> tuple[str, int]:
    digest = sha256_bytes(payload)
    return write_blob_payload(image_path, digest, payload)


def write_blob_payload(image_path: Path, digest: str, payload: bytes) -> tuple[str, int]:
    actual_digest = sha256_bytes(payload)
    if actual_digest != digest:
        raise ValueError(f"blob digest mismatch: expected {digest}, got {actual_digest}")
    target = blob_path(image_path, digest)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        tmp_path = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        with open(tmp_path, "wb") as handle:
            handle.write(payload)
        os.replace(tmp_path, target)
    return digest, len(payload)


def store_blob_file(image_path: Path, source: Path) -> tuple[str, int]:
    digest = sha256_file(source)
    target = blob_path(image_path, digest)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copy2(source, target)
    return digest, target.stat().st_size


def create_layer_blob(rootfs: Path, image_path: Path, exclude_names: set[str] | None = None) -> tuple[str, int]:
    image_path.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(prefix="layer-", suffix=".tar", dir=image_path.parent, delete=False) as handle:
        tmp_path = Path(handle.name)
    try:
        with tarfile.open(tmp_path, "w", format=tarfile.PAX_FORMAT) as archive:
            for item in sorted(rootfs.iterdir(), key=lambda path: path.name):
                if exclude_names and item.name in exclude_names:
                    continue
                archive.add(item, arcname=item.name, recursive=True)
        return store_blob_file(image_path, tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def parse_image_reference_for_registry(image: str) -> tuple[str, str, str]:
    ref = image.removeprefix("docker://")
    if "://" in ref:
        raise ValueError(f"unsupported image reference scheme: {image}")

    digest = None
    if "@" in ref:
        name, digest = ref.split("@", 1)
        reference = digest
    else:
        name = ref
        last_component = ref.rsplit("/", 1)[-1]
        if ":" in last_component:
            name, reference = ref.rsplit(":", 1)
        else:
            reference = "latest"

    if not name:
        raise ValueError(f"invalid image reference: {image}")

    parts = name.split("/")
    if len(parts) == 1:
        return "registry-1.docker.io", f"library/{parts[0]}", reference

    first = parts[0]
    if "." in first or ":" in first or first == "localhost":
        registry = "registry-1.docker.io" if first == "docker.io" else first
        repository = "/".join(parts[1:])
    else:
        registry = "registry-1.docker.io"
        repository = name

    if not repository:
        raise ValueError(f"invalid image reference: {image}")
    return registry, repository, reference


def registry_scheme(registry: str) -> str:
    if registry.startswith("localhost") or registry.startswith("127.") or registry.startswith("[::1]"):
        return "http"
    return "https"


def parse_www_authenticate(header: str) -> tuple[str, dict[str, str]]:
    scheme, _, params_text = header.partition(" ")
    params: dict[str, str] = {}
    for match in re.finditer(r'([A-Za-z_][A-Za-z0-9_-]*)=(?:"([^"]*)"|([^,]*))', params_text):
        params[match.group(1).lower()] = match.group(2) if match.group(2) is not None else match.group(3).strip()
    return scheme.lower(), params


class RegistryClient:
    def __init__(self, registry: str):
        self.registry = registry
        self.base_url = f"{registry_scheme(registry)}://{registry}"
        self._bearer_token: str | None = None

    def get_manifest(self, repository: str, reference: str) -> tuple[bytes, Any]:
        return self.get(
            f"/v2/{repository}/manifests/{quote(reference, safe=':@')}",
            accept=REGISTRY_MANIFEST_ACCEPT,
        )

    def get_blob(self, repository: str, digest: str) -> tuple[bytes, Any]:
        return self.get(f"/v2/{repository}/blobs/{quote(digest, safe=':')}")

    def get(self, path: str, accept: str | None = None) -> tuple[bytes, Any]:
        url = path if path.startswith("http://") or path.startswith("https://") else self.base_url + path
        return self._request(url, accept=accept, retry_auth=True)

    def _request(self, url: str, accept: str | None = None, retry_auth: bool = True) -> tuple[bytes, Any]:
        headers = {"User-Agent": "pnfroot/0.1"}
        if accept:
            headers["Accept"] = accept
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=60) as response:
                return response.read(), response.headers
        except Exception as exc:
            code = getattr(exc, "code", None)
            auth_header = getattr(exc, "headers", {}).get("WWW-Authenticate") if getattr(exc, "headers", None) else None
            if code == 401 and retry_auth and auth_header:
                self._bearer_token = self._fetch_bearer_token(auth_header)
                return self._request(url, accept=accept, retry_auth=False)
            raise

    def _fetch_bearer_token(self, auth_header: str) -> str:
        scheme, params = parse_www_authenticate(auth_header)
        if scheme != "bearer" or not params.get("realm"):
            raise PermissionError(f"unsupported registry auth challenge: {auth_header}")
        query = dict(parse_qsl(urlsplit(params["realm"]).query))
        for key in ("service", "scope"):
            if params.get(key):
                query[key] = params[key]
        token_url = params["realm"].split("?", 1)[0]
        if query:
            token_url = f"{token_url}?{urlencode(query)}"
        request = Request(token_url, headers={"User-Agent": "pnfroot/0.1"})
        with urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode("utf-8"))
        token = payload.get("token") or payload.get("access_token")
        if not token:
            raise PermissionError("registry token response did not include a token")
        return token


def platform_parts(platform: str) -> tuple[str, str, str | None]:
    parts = platform.split("/")
    if len(parts) < 2:
        raise ValueError(f"invalid platform: {platform}")
    variant = parts[2] if len(parts) > 2 else None
    return parts[0], parts[1], variant


def manifest_is_index(manifest: dict[str, Any]) -> bool:
    media_type = manifest.get("mediaType", "")
    return media_type in {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    } or bool(manifest.get("manifests"))


def select_platform_manifest(index: dict[str, Any], platform: str) -> dict[str, Any]:
    want_os, want_arch, want_variant = platform_parts(platform)
    fallback = None
    for descriptor in index.get("manifests", []):
        entry_platform = descriptor.get("platform") or {}
        if entry_platform.get("os") != want_os or entry_platform.get("architecture") != want_arch:
            continue
        entry_variant = entry_platform.get("variant")
        if want_variant is None or entry_variant == want_variant:
            return descriptor
        fallback = fallback or descriptor
    if fallback is not None:
        return fallback
    raise FileNotFoundError(f"no {platform} manifest in image index")


def pull_registry_image_to_store(image: str, image_store_dir: str | os.PathLike[str], platform: str = IMAGE_PLATFORM) -> dict[str, Any]:
    image_ref = normalize_image_ref(image.removeprefix("docker://"))
    image_path = Path(image_store_dir) / image_dir_name(image_ref)
    image_path.mkdir(parents=True, exist_ok=True)

    registry, repository, reference = parse_image_reference_for_registry(image)
    client = RegistryClient(registry)
    manifest_payload, manifest_headers = client.get_manifest(repository, reference)
    manifest = json.loads(manifest_payload.decode("utf-8"))

    if manifest_is_index(manifest):
        descriptor = select_platform_manifest(manifest, platform)
        manifest_payload, manifest_headers = client.get_manifest(repository, descriptor["digest"])
        manifest = json.loads(manifest_payload.decode("utf-8"))

    if manifest.get("schemaVersion") != 2 or not manifest.get("layers"):
        raise ValueError(f"unsupported image manifest for {image}")

    manifest_digest = manifest_headers.get("Docker-Content-Digest") or sha256_bytes(manifest_payload)
    write_blob_payload(image_path, manifest_digest, manifest_payload)

    config = manifest.get("config") or {}
    config_digest = config.get("digest")
    if not config_digest:
        raise ValueError(f"image manifest has no config digest: {image}")
    config_payload, _ = client.get_blob(repository, config_digest)
    _, config_size = write_blob_payload(image_path, config_digest, config_payload)

    layer_digests: list[str] = []
    total_size = len(manifest_payload) + config_size
    for layer in manifest.get("layers", []):
        media_type = layer.get("mediaType", "")
        digest = layer.get("digest")
        if not digest:
            raise ValueError(f"image layer has no digest: {image}")
        if media_type and media_type not in REGISTRY_LAYER_MEDIA_TYPES:
            raise ValueError(f"unsupported layer media type {media_type!r} for {image}")
        target = blob_path(image_path, digest)
        if target.exists() and sha256_file(target) == digest:
            layer_size = target.stat().st_size
        else:
            layer_payload, _ = client.get_blob(repository, digest)
            _, layer_size = write_blob_payload(image_path, digest, layer_payload)
        layer_digests.append(digest)
        total_size += layer_size

    img = image_metadata(image_ref, image_path)
    img.update(
        {
            "image_id": manifest_digest,
            "manifest_digest": manifest_digest,
            "manifest_size": len(manifest_payload),
            "config_digest": config_digest,
            "layer_digests": layer_digests,
            "size": total_size,
            "source_type": "registry",
            "source_image": image,
            "registry": registry,
            "repository": repository,
            "platform": platform,
        }
    )
    write_image_metadata(img)
    return img


def pull_image_to_store(image: str, image_store_dir: str | os.PathLike[str], platform: str = IMAGE_PLATFORM) -> dict[str, Any]:
    image_ref = normalize_image_ref(image.removeprefix("docker://"))
    image_path = Path(image_store_dir) / image_dir_name(image_ref)
    image_path.mkdir(parents=True, exist_ok=True)
    try:
        source = resolve_local_image_source(image)
    except FileNotFoundError:
        if is_local_image_reference(image):
            raise
        return pull_registry_image_to_store(image, image_store_dir=image_store_dir, platform=platform)
    if not source.is_dir():
        raise FileNotFoundError(f"image source {source} is not an unpacked rootfs directory")

    layer_digest, layer_size = create_layer_blob(source, image_path)
    config_payload = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
            "created": cri_time_ns(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    config_digest, config_size = write_blob_bytes(image_path, config_payload)
    manifest_payload = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config_size,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": layer_digest,
                    "size": layer_size,
                }
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    manifest_digest, manifest_size = write_blob_bytes(image_path, manifest_payload)
    img = image_metadata(image_ref, image_path)
    img.update(
        {
            "image_id": manifest_digest,
            "manifest_digest": manifest_digest,
            "manifest_size": manifest_size,
            "config_digest": config_digest,
            "layer_digests": [layer_digest],
            "size": layer_size + config_size + manifest_size,
            "source_type": "local-rootfs",
            "source_image": image,
            "platform": platform,
        }
    )
    write_image_metadata(img)
    return img


def image_dir_has_layers(image_path: Path) -> bool:
    img = read_image_metadata(image_path)
    return bool(img and img.get("layer_digests"))


def migrate_legacy_rootfs_image(image_path: Path, image_ref: str) -> dict[str, Any]:
    layer_digest, layer_size = create_layer_blob(
        image_path,
        image_path,
        exclude_names={"blobs", IMAGE_METADATA_FILE},
    )
    config_payload = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
            "created": cri_time_ns(),
            "pnfrootLegacyMigration": True,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    config_digest, config_size = write_blob_bytes(image_path, config_payload)
    manifest_payload = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config_size,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": layer_digest,
                    "size": layer_size,
                }
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    manifest_digest, manifest_size = write_blob_bytes(image_path, manifest_payload)
    img = image_metadata(image_ref, image_path)
    img.update(
        {
            "image_id": manifest_digest,
            "manifest_digest": manifest_digest,
            "manifest_size": manifest_size,
            "config_digest": config_digest,
            "layer_digests": [layer_digest],
            "size": layer_size + config_size + manifest_size,
            "source_type": "legacy-rootfs",
            "source_image": image_ref,
        }
    )
    write_image_metadata(img)
    cleanup_legacy_rootfs_entries(image_path)
    return img


def cleanup_legacy_rootfs_entries(image_path: Path) -> None:
    for item in image_path.iterdir():
        if item.name in {"blobs", IMAGE_METADATA_FILE}:
            continue
        if item.is_symlink() or item.is_file():
            item.unlink()
        elif item.is_dir():
            shutil.rmtree(item)


def unpack_image_to_rootfs(image_path: Path, rootfs_path: Path) -> Path:
    img = read_image_metadata(image_path)
    if img is None:
        raise FileNotFoundError(f"image metadata not found in {image_path}")
    layer_digests = img.get("layer_digests") or []
    if not layer_digests:
        raise FileNotFoundError(f"image has no layers: {image_path}")
    if rootfs_path.exists():
        shutil.rmtree(rootfs_path)
    rootfs_path.mkdir(parents=True, exist_ok=True)
    try:
        for digest in layer_digests:
            extract_tar_safe(blob_path(image_path, digest), rootfs_path)
    except Exception:
        shutil.rmtree(rootfs_path, ignore_errors=True)
        raise
    return rootfs_path


def extract_tar_safe(layer_path: Path, rootfs_path: Path) -> None:
    rootfs = rootfs_path.resolve()
    with tarfile.open(layer_path, "r:*") as archive:
        for member in archive:
            name = member.name.lstrip("./")
            if not name:
                continue
            target = (rootfs / name).resolve()
            if target != rootfs and rootfs not in target.parents:
                raise ValueError(f"unsafe image layer path: {member.name}")

            base = os.path.basename(name)
            parent = target.parent

            if base.startswith(".wh."):
                if base == ".wh..wh..opq":
                    if parent.exists():
                        for child in parent.iterdir():
                            if child.is_dir() and not child.is_symlink():
                                shutil.rmtree(child)
                            else:
                                child.unlink(missing_ok=True)
                else:
                    victim = parent / base[4:]
                    if victim.is_dir() and not victim.is_symlink():
                        shutil.rmtree(victim)
                    else:
                        victim.unlink(missing_ok=True)
                continue

            archive.extract(member, rootfs, filter="fully_trusted")


def _copy_tree_safe(src: Path, dst: Path) -> None:
    for item in src.iterdir():
        target = dst / item.name
        if item.is_symlink():
            if os.path.lexists(target):
                target.unlink()
            target.symlink_to(os.readlink(item))
            continue
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            _copy_tree_safe(item, target)
        elif item.is_file():
            shutil.copy2(item, target)


class ExecStreamRequest:
    def __init__(
        self,
        *,
        container_id: str,
        cmd: list[str],
        tty: bool,
        stdin: bool,
        stdout: bool,
        stderr: bool,
        created_at: float,
    ):
        self.container_id = container_id
        self.cmd = cmd
        self.tty = tty
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.created_at = created_at


class RemoteCommandHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class WebSocketConnection:
    def __init__(self, sock: socket.socket, protocol: str):
        self.sock = sock
        self.protocol = protocol
        self.base64_channel = "base64" in protocol
        self.write_lock = threading.Lock()
        self.closed = False

    @classmethod
    def accept(cls, handler: http.server.BaseHTTPRequestHandler, protocol: str) -> "WebSocketConnection":
        key = handler.headers.get("Sec-WebSocket-Key")
        if not key:
            raise ValueError("missing Sec-WebSocket-Key")
        try:
            base64.b64decode(key.encode("ascii"), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid Sec-WebSocket-Key") from exc

        accept = base64.b64encode(hashlib.sha1((key + WEBSOCKET_GUID).encode("ascii")).digest()).decode("ascii")
        headers = [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Accept: {accept}",
        ]
        if protocol:
            headers.append(f"Sec-WebSocket-Protocol: {protocol}")
        handler.request.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        return cls(handler.request, protocol)

    def _recv_exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise EOFError("websocket closed")
            data.extend(chunk)
        return bytes(data)

    def _send_frame(self, opcode: int, payload: bytes = b"") -> None:
        if self.closed:
            return
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(length)
        elif length <= 0xFFFF:
            header.extend([126])
            header.extend(struct.pack("!H", length))
        else:
            header.extend([127])
            header.extend(struct.pack("!Q", length))
        with self.write_lock:
            if self.closed:
                return
            self.sock.sendall(bytes(header) + payload)

    def read_channel_message(self) -> tuple[int, bytes]:
        while True:
            first, second = self._recv_exact(2)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]

            mask = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(length) if length else b""
            if masked:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))

            if opcode == 0x8:
                raise EOFError("websocket close frame")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode not in {0x1, 0x2}:
                continue

            if opcode == 0x1 or self.base64_channel:
                payload = base64.b64decode(payload)
            if not payload:
                continue
            return payload[0], payload[1:]

    def send_channel(self, channel: int, data: bytes = b"") -> None:
        payload = bytes([channel]) + data
        if self.base64_channel:
            self._send_frame(0x1, base64.b64encode(payload))
        else:
            self._send_frame(0x2, payload)

    def close(self) -> None:
        with self.write_lock:
            if self.closed:
                return
            self.closed = True
            try:
                payload = struct.pack("!H", 1000)
                header = bytes([0x88, len(payload)])
                self.sock.sendall(header + payload)
            except OSError:
                pass
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass


class SpdyRemoteCommandConnection:
    channel_to_stream_type = {
        STREAM_STDIN: "stdin",
        STREAM_STDOUT: "stdout",
        STREAM_STDERR: "stderr",
        STREAM_ERROR: "error",
        STREAM_RESIZE: "resize",
    }
    stream_type_to_channel = {
        "stdin": STREAM_STDIN,
        "stdout": STREAM_STDOUT,
        "stderr": STREAM_STDERR,
        "error": STREAM_ERROR,
        "resize": STREAM_RESIZE,
    }

    def __init__(self, sock: socket.socket, protocol: str):
        self.sock = sock
        self.protocol = protocol
        self.write_lock = threading.Lock()
        self.closed = False
        self.streams_by_id: dict[int, str] = {}
        self.streams_by_type: dict[str, int] = {}
        self.local_finished: set[int] = set()
        self.remote_finished: set[int] = set()
        self.incoming: queue.Queue[tuple[int, bytes]] = queue.Queue()
        self.streams_changed = threading.Condition()
        self.header_compressor = zlib.compressobj(
            level=zlib.Z_BEST_COMPRESSION,
            wbits=zlib.MAX_WBITS,
            zdict=SPDY_HEADER_DICTIONARY,
        )
        self.header_decompressor = zlib.decompressobj(
            wbits=zlib.MAX_WBITS,
            zdict=SPDY_HEADER_DICTIONARY,
        )
        self.reader = threading.Thread(target=self._read_loop, name="pnfroot-spdy", daemon=True)
        self.reader.start()

    @classmethod
    def accept(cls, handler: http.server.BaseHTTPRequestHandler, protocol: str) -> "SpdyRemoteCommandConnection":
        headers = [
            "HTTP/1.1 101 Switching Protocols",
            "Connection: Upgrade",
            f"Upgrade: {SPDY_UPGRADE}",
            f"X-Stream-Protocol-Version: {protocol}",
        ]
        handler.request.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
        return cls(handler.request, protocol)

    def wait_for_streams(self, request: ExecStreamRequest, timeout: float = 30.0) -> None:
        expected = {"error"}
        if request.stdin:
            expected.add("stdin")
        if request.stdout:
            expected.add("stdout")
        if request.stderr and not request.tty:
            expected.add("stderr")
        deadline = time.monotonic() + timeout
        with self.streams_changed:
            while not expected.issubset(self.streams_by_type):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    missing = sorted(expected - set(self.streams_by_type))
                    raise TimeoutError(f"timed out waiting for SPDY streams: {', '.join(missing)}")
                self.streams_changed.wait(timeout=remaining)

    def _recv_exact(self, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise EOFError("spdy closed")
            data.extend(chunk)
        return bytes(data)

    def _read_loop(self) -> None:
        try:
            while not self.closed:
                self._read_frame()
        except (EOFError, OSError, zlib.error, struct.error):
            pass
        finally:
            self.closed = True
            self.incoming.put((STREAM_CLOSE, b""))
            with self.streams_changed:
                self.streams_changed.notify_all()

    def _read_frame(self) -> None:
        first_word = struct.unpack("!I", self._recv_exact(4))[0]
        flags_and_length = struct.unpack("!I", self._recv_exact(4))[0]
        flags = (flags_and_length >> 24) & 0xFF
        length = flags_and_length & 0xFFFFFF
        payload = self._recv_exact(length) if length else b""

        if first_word & 0x80000000:
            version = (first_word >> 16) & 0x7FFF
            frame_type = first_word & 0xFFFF
            if version != SPDY_VERSION:
                raise EOFError(f"unsupported SPDY version {version}")
            self._handle_control_frame(frame_type, flags, payload)
            return

        stream_id = first_word & 0x7FFFFFFF
        self._handle_data_frame(stream_id, flags, payload)

    def _handle_control_frame(self, frame_type: int, flags: int, payload: bytes) -> None:
        if frame_type == SPDY_TYPE_SYN_STREAM:
            self._handle_syn_stream(flags, payload)
        elif frame_type == SPDY_TYPE_RST_STREAM:
            if len(payload) >= 4:
                stream_id = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
                self._finish_remote_stream(stream_id)
        elif frame_type == SPDY_TYPE_PING:
            if len(payload) == 4:
                self._write_control_frame(SPDY_TYPE_PING, 0, payload)
        elif frame_type == SPDY_TYPE_GOAWAY:
            raise EOFError("spdy goaway")
        elif frame_type in {SPDY_TYPE_SETTINGS, SPDY_TYPE_HEADERS, SPDY_TYPE_WINDOW_UPDATE, SPDY_TYPE_SYN_REPLY}:
            return

    def _handle_syn_stream(self, flags: int, payload: bytes) -> None:
        if len(payload) < 10:
            return
        stream_id = struct.unpack("!I", payload[:4])[0] & 0x7FFFFFFF
        headers = self._parse_header_block(self.header_decompressor.decompress(payload[10:]))
        stream_type = headers.get("streamtype", [""])[0]
        if stream_type not in self.stream_type_to_channel:
            self._write_rst_stream(stream_id, SPDY_STATUS_CANCEL)
            return

        with self.streams_changed:
            self.streams_by_id[stream_id] = stream_type
            self.streams_by_type[stream_type] = stream_id
            if flags & SPDY_FLAG_FIN:
                self.remote_finished.add(stream_id)
            self.streams_changed.notify_all()
        self._write_syn_reply(stream_id)
        if flags & SPDY_FLAG_FIN:
            self._queue_remote_finish(stream_id)

    def _handle_data_frame(self, stream_id: int, flags: int, payload: bytes) -> None:
        stream_type = self.streams_by_id.get(stream_id)
        if stream_type is None:
            return
        channel = self.stream_type_to_channel[stream_type]
        if payload and channel in {STREAM_STDIN, STREAM_RESIZE}:
            self.incoming.put((channel, payload))
        if flags & SPDY_FLAG_FIN:
            self._finish_remote_stream(stream_id)

    def _finish_remote_stream(self, stream_id: int) -> None:
        if stream_id in self.remote_finished:
            return
        self.remote_finished.add(stream_id)
        self._queue_remote_finish(stream_id)

    def _queue_remote_finish(self, stream_id: int) -> None:
        stream_type = self.streams_by_id.get(stream_id)
        if stream_type == "stdin":
            self.incoming.put((STREAM_CLOSE, bytes([STREAM_STDIN])))

    def _parse_header_block(self, data: bytes) -> dict[str, list[str]]:
        offset = 0
        if len(data) < 4:
            return {}
        count = struct.unpack("!I", data[offset : offset + 4])[0]
        offset += 4
        headers: dict[str, list[str]] = {}
        for _ in range(count):
            if offset + 4 > len(data):
                break
            name_len = struct.unpack("!I", data[offset : offset + 4])[0]
            offset += 4
            name = data[offset : offset + name_len].decode("utf-8", "replace").lower()
            offset += name_len
            if offset + 4 > len(data):
                break
            value_len = struct.unpack("!I", data[offset : offset + 4])[0]
            offset += 4
            value = data[offset : offset + value_len].decode("utf-8", "replace")
            offset += value_len
            headers[name] = value.split("\x00") if value else [""]
        return headers

    def _header_block(self, headers: dict[str, list[str] | str]) -> bytes:
        raw = bytearray()
        raw.extend(struct.pack("!I", len(headers)))
        for name, values in headers.items():
            header_name = name.lower().encode("utf-8")
            if isinstance(values, str):
                header_value = values.encode("utf-8")
            else:
                header_value = "\x00".join(values).encode("utf-8")
            raw.extend(struct.pack("!I", len(header_name)))
            raw.extend(header_name)
            raw.extend(struct.pack("!I", len(header_value)))
            raw.extend(header_value)
        return self.header_compressor.compress(bytes(raw)) + self.header_compressor.flush(zlib.Z_SYNC_FLUSH)

    def _write_control_frame(self, frame_type: int, flags: int, payload: bytes) -> None:
        header = struct.pack(
            "!HHI",
            0x8000 | SPDY_VERSION,
            frame_type,
            ((flags & 0xFF) << 24) | (len(payload) & 0xFFFFFF),
        )
        with self.write_lock:
            if not self.closed:
                self.sock.sendall(header + payload)

    def _write_data_frame(self, stream_id: int, data: bytes = b"", fin: bool = False) -> None:
        if stream_id in self.local_finished:
            return
        flags = SPDY_FLAG_FIN if fin else 0
        header = struct.pack("!II", stream_id & 0x7FFFFFFF, (flags << 24) | (len(data) & 0xFFFFFF))
        with self.write_lock:
            if self.closed:
                return
            self.sock.sendall(header + data)
            if fin:
                self.local_finished.add(stream_id)

    def _write_syn_reply(self, stream_id: int) -> None:
        payload = struct.pack("!I", stream_id & 0x7FFFFFFF) + self._header_block({})
        self._write_control_frame(SPDY_TYPE_SYN_REPLY, 0, payload)

    def _write_rst_stream(self, stream_id: int, status: int) -> None:
        self._write_control_frame(SPDY_TYPE_RST_STREAM, 0, struct.pack("!II", stream_id & 0x7FFFFFFF, status))

    def read_channel_message(self) -> tuple[int, bytes]:
        channel, payload = self.incoming.get()
        if channel == STREAM_CLOSE and not payload:
            raise EOFError("spdy closed")
        return channel, payload

    def send_channel(self, channel: int, data: bytes = b"") -> None:
        stream_type = self.channel_to_stream_type.get(channel)
        if stream_type is None:
            return
        with self.streams_changed:
            stream_id = self.streams_by_type.get(stream_type)
        if stream_id is None:
            return
        if data:
            self._write_data_frame(stream_id, data)

    def close(self) -> None:
        already_closed = self.closed
        if not already_closed:
            for stream_id in list(self.streams_by_id):
                try:
                    self._write_data_frame(stream_id, fin=True)
                except OSError:
                    break
            try:
                last_stream_id = max(self.streams_by_id) if self.streams_by_id else 0
                self._write_control_frame(SPDY_TYPE_GOAWAY, 0, struct.pack("!II", last_stream_id, 0))
            except OSError:
                pass
        self.closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class RemoteCommandRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug("stream %s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        self._handle_request()

    def do_POST(self) -> None:
        self._handle_request()

    def _handle_request(self) -> None:
        manager: RemoteCommandServer = self.server.remote_command_server  # type: ignore[attr-defined]
        parsed = urlsplit(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 2 or parts[0] != "exec":
            self.send_error(404, "not found")
            return

        request = manager.consume_exec(parts[1])
        if request is None:
            self.send_error(404, "exec request not found")
            return

        self.close_connection = True
        if self._is_websocket_request():
            protocol = manager.negotiate_websocket_protocol(self.headers.get("Sec-WebSocket-Protocol", ""))
            if protocol is None:
                self.send_error(400, "unsupported websocket protocol")
                return
            try:
                stream = WebSocketConnection.accept(self, protocol)
            except ValueError as exc:
                self.send_error(400, str(exc))
                return
            manager.serve_exec(request, stream)
            return

        if self._is_spdy_request():
            protocol = manager.negotiate_spdy_protocol(self.headers.get_all("X-Stream-Protocol-Version") or [])
            if protocol is None:
                self.send_error(400, "unsupported SPDY stream protocol")
                return
            stream = SpdyRemoteCommandConnection.accept(self, protocol)
            manager.serve_exec(request, stream)
            return

        self.send_error(426, "websocket or SPDY upgrade required")

    def _is_websocket_request(self) -> bool:
        connection = self.headers.get("Connection", "").lower()
        upgrade = self.headers.get("Upgrade", "").lower()
        return "upgrade" in connection and upgrade == "websocket"

    def _is_spdy_request(self) -> bool:
        connection = self.headers.get("Connection", "").lower()
        upgrade = self.headers.get("Upgrade", "").lower()
        return "upgrade" in connection and upgrade == SPDY_UPGRADE.lower()


class RemoteCommandServer:
    def __init__(
        self,
        runtime: "RuntimeService",
        host: str = STREAM_HOST,
        port: int = STREAM_PORT,
        public_host: str | None = None,
        token_ttl_seconds: int = STREAM_TOKEN_TTL_SECONDS,
    ):
        self.runtime = runtime
        self.host = host
        self.port = port
        self.public_host = public_host
        self.token_ttl_seconds = token_ttl_seconds
        self._lock = threading.Lock()
        self._requests: dict[str, ExecStreamRequest] = {}
        self._server: RemoteCommandHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.start()

    @property
    def base_url(self) -> str:
        if self._server is None:
            self.start()
        assert self._server is not None
        host = self.public_host or self.host
        if host in {"", "0.0.0.0"}:
            host = "127.0.0.1"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{self._server.server_address[1]}"

    def start(self) -> None:
        if self._server is not None:
            return
        self._server = RemoteCommandHTTPServer((self.host, self.port), RemoteCommandRequestHandler)
        self._server.remote_command_server = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, name="pnfroot-streaming", daemon=True)
        self._thread.start()
        logger.info("CRI streaming server started on %s", self.base_url)

    def shutdown(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None

    def build_exec_url(self, request: ExecStreamRequest) -> str:
        token = uuid.uuid4().hex
        with self._lock:
            self._drop_expired_locked()
            self._requests[token] = request
        return f"{self.base_url}/exec/{token}"

    def consume_exec(self, token: str) -> ExecStreamRequest | None:
        with self._lock:
            request = self._requests.pop(token, None)
            if request is None:
                return None
            if time.time() - request.created_at > self.token_ttl_seconds:
                return None
            return request

    def _drop_expired_locked(self) -> None:
        now = time.time()
        expired = [
            token
            for token, request in self._requests.items()
            if now - request.created_at > self.token_ttl_seconds
        ]
        for token in expired:
            self._requests.pop(token, None)

    def negotiate_websocket_protocol(self, offered_header: str) -> str | None:
        if not offered_header:
            return "channel.k8s.io"
        offered = [item.strip() for item in offered_header.split(",") if item.strip()]
        for protocol in offered:
            if protocol in WEBSOCKET_PROTOCOLS:
                return protocol
        return None

    def negotiate_spdy_protocol(self, offered_headers: list[str]) -> str | None:
        if not offered_headers:
            return "channel.k8s.io"
        offered: list[str] = []
        for header in offered_headers:
            offered.extend(item.strip() for item in header.split(",") if item.strip())
        for protocol in offered:
            if protocol in CHANNEL_PROTOCOLS:
                return protocol
        return None

    def serve_exec(self, request: ExecStreamRequest, stream: Any) -> None:
        stop_event = threading.Event()
        process: Any = None
        pty_master: int | None = None
        stdin_closed = threading.Event()

        def send_status(exit_code: int, message: str | None = None) -> None:
            if stream.protocol in {"v4.channel.k8s.io", "v5.channel.k8s.io", "v4.base64.channel.k8s.io"}:
                if exit_code == 0 and message is None:
                    status = {"status": "Success"}
                elif message is None:
                    status = {
                        "status": "Failure",
                        "reason": "NonZeroExitCode",
                        "message": f"command terminated with non-zero exit code: {exit_code}",
                        "details": {
                            "causes": [
                                {
                                    "reason": "ExitCode",
                                    "message": str(exit_code),
                                }
                            ]
                        },
                    }
                else:
                    status = {
                        "status": "Failure",
                        "reason": "InternalError",
                        "message": f"Internal error occurred: {message}",
                        "code": 500,
                    }
                stream.send_channel(STREAM_ERROR, json.dumps(status, separators=(",", ":")).encode("utf-8"))
            elif exit_code != 0 or message is not None:
                stream.send_channel(STREAM_ERROR, (message or f"command exited with {exit_code}").encode("utf-8"))

        def close_stdin() -> None:
            if stdin_closed.is_set():
                return
            stdin_closed.set()
            if process is not None and process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass

        def pipe_to_channel(pipe: Any, channel: int) -> None:
            try:
                while not stop_event.is_set():
                    data = pipe.read(32768)
                    if not data:
                        break
                    stream.send_channel(channel, data)
            except OSError:
                pass
            finally:
                try:
                    pipe.close()
                except OSError:
                    pass

        def pty_to_stdout(fd: int) -> None:
            try:
                while not stop_event.is_set():
                    try:
                        data = os.read(fd, 32768)
                    except OSError:
                        break
                    if not data:
                        break
                    stream.send_channel(STREAM_STDOUT, data)
            finally:
                try:
                    os.close(fd)
                except OSError:
                    pass

        def apply_resize(payload: bytes) -> None:
            if pty_master is None:
                return
            try:
                size = json.loads(payload.decode("utf-8"))
                width = int(size.get("Width", size.get("width", 0)))
                height = int(size.get("Height", size.get("height", 0)))
                if width > 0 and height > 0:
                    fcntl.ioctl(pty_master, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
            except (OSError, ValueError, json.JSONDecodeError):
                pass

        def receive_loop() -> None:
            try:
                while not stop_event.is_set():
                    channel, payload = stream.read_channel_message()
                    if channel == STREAM_STDIN and request.stdin:
                        if request.tty and pty_master is not None:
                            os.write(pty_master, payload)
                        elif process is not None and process.stdin is not None and not stdin_closed.is_set():
                            process.stdin.write(payload)
                            process.stdin.flush()
                    elif channel == STREAM_RESIZE:
                        apply_resize(payload)
                    elif channel == STREAM_CLOSE:
                        if payload and payload[0] == STREAM_STDIN:
                            close_stdin()
            except (EOFError, OSError, BrokenPipeError):
                close_stdin()
                if not stop_event.is_set() and process is not None and process.poll() is None:
                    process.terminate()

        output_threads: list[threading.Thread] = []
        receiver: threading.Thread | None = None
        try:
            container = self.runtime.find_container(request.container_id)
            if container is None:
                send_status(1, "container not found")
                return

            if isinstance(stream, SpdyRemoteCommandConnection):
                stream.wait_for_streams(request)

            process, pty_master = self.runtime.start_exec_process(
                container,
                request.cmd,
                tty=request.tty,
                stdin=request.stdin,
                stdout=request.stdout,
                stderr=request.stderr,
            )

            if request.stdout:
                stream.send_channel(STREAM_STDOUT, b"")
            elif request.stderr:
                stream.send_channel(STREAM_STDERR, b"")
            else:
                stream.send_channel(STREAM_ERROR, b"")

            if request.tty and pty_master is not None:
                output_threads.append(threading.Thread(target=pty_to_stdout, args=(pty_master,), daemon=True))
            else:
                if request.stdout and process.stdout is not None:
                    output_threads.append(threading.Thread(target=pipe_to_channel, args=(process.stdout, STREAM_STDOUT), daemon=True))
                if request.stderr and process.stderr is not None:
                    output_threads.append(threading.Thread(target=pipe_to_channel, args=(process.stderr, STREAM_STDERR), daemon=True))

            for thread in output_threads:
                thread.start()

            receiver = threading.Thread(target=receive_loop, daemon=True)
            receiver.start()
            exit_code = process.wait()
            close_stdin()
            for thread in output_threads:
                thread.join(timeout=2)
            send_status(exit_code)
        except Exception as exc:
            logger.exception("Exec stream failed")
            send_status(1, str(exc))
            if process is not None and process.poll() is None:
                process.kill()
        finally:
            stop_event.set()
            stream.close()
            if receiver is not None:
                receiver.join(timeout=1)


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
        return normalize_image_ref(image.removeprefix("docker://"))

    def image_dir_name(self, image_ref: str) -> str:
        return image_dir_name(image_ref)

    def image_path(self, image_ref: str) -> Path:
        return self.image_store_dir / self.image_dir_name(image_ref)

    def metadata_path(self, image_path: Path) -> Path:
        return image_path / IMAGE_METADATA_FILE

    def path_size(self, path: Path) -> int:
        return path_size(path)

    def path_inodes(self, path: Path) -> int:
        return sum(1 for _ in path.rglob("*"))

    def read_metadata(self, image_path: Path) -> dict[str, Any] | None:
        return read_image_metadata(image_path)

    def write_metadata(self, img: dict[str, Any]) -> None:
        write_image_metadata(img)

    def normalize_repo_tags(self, img: dict[str, Any]) -> list[str]:
        repo_tags = img.get("repo_tags") or []
        if repo_tags:
            canonical = [tag for tag in repo_tags if isinstance(tag, str) and tag]
            if canonical:
                return [canonical[0]]
        image_id = img.get("image_id") or img.get("id") or "local:latest"
        return [str(image_id)]

    def load_images(self) -> None:
        for image_path in self.image_store_dir.iterdir():
            if not image_path.is_dir():
                continue
            img = self.read_metadata(image_path)
            if img is None or not img.get("layer_digests"):
                image_ref = (img or {}).get("id") or infer_image_ref_from_dir_name(image_path.name)
                legacy_entries = [
                    item
                    for item in image_path.iterdir()
                    if item.name not in {"blobs", IMAGE_METADATA_FILE}
                ]
                if legacy_entries:
                    img = migrate_legacy_rootfs_image(image_path, str(image_ref))
                else:
                    continue
            img["path"] = str(image_path)
            img["size"] = self.path_size(image_path)
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

        image_ref = self.normalize_image_ref(image.removeprefix("docker://"))
        try:
            img = pull_image_to_store(image=image, image_store_dir=self.image_store_dir, platform=self.platform)
        except Exception as exc:
            logger.exception("PullImage failed for %s", image)
            await context.abort(grpc.StatusCode.UNKNOWN, f"pull image failed: {exc}")

        repo_tags = [image_ref]
        img["repo_tags"] = repo_tags
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
            "envs": dict(container.get("envs") or {}),
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
            "envs": dict(data.get("envs") or {}),
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

    def image_path(self, image_ref: str) -> Path:
        return self.image_store_dir / self._image_dir_name(image_ref)

    def image_available(self, image_ref: str) -> bool:
        image_path = self.image_path(image_ref)
        return image_path.exists() and image_dir_has_layers(image_path)

    def image_cache_needs_refresh(self, image_ref: str, image_name: str | None = None) -> bool:
        image = image_name or image_ref
        if not image or is_local_image_reference(image) or local_image_source_exists(image):
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
        if image_path.exists():
            img = read_image_metadata(image_path)
            image_ref_for_migration = (img or {}).get("id") or image_ref
            legacy_entries = [
                item
                for item in image_path.iterdir()
                if item.name not in {"blobs", IMAGE_METADATA_FILE}
            ]
            if legacy_entries:
                migrate_legacy_rootfs_image(image_path, str(image_ref_for_migration))
                return image_path
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
        env.update(container["envs"])
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
