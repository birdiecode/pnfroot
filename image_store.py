from __future__ import annotations

import ast
import hashlib
import json
import os
import platform as host_platform
import re
import shutil
import tarfile
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from cri_common import logger, normalize_image_ref


def default_image_platform(machine: str | None = None) -> str:
    machine = (machine or host_platform.machine()).lower()
    architecture = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)
    if architecture is None:
        raise RuntimeError(f"unsupported host architecture: {machine}")
    return f"linux/{architecture}"


IMAGE_PLATFORM = default_image_platform()
DEFAULT_IMAGE_SIZE = 1
IMAGE_METADATA_FILE = "pnfroot-image.json"
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
    if is_local_image_reference(image):
        raise ValueError("local rootfs image sources are not supported by pnfroot; use ptrace_syscalls.py --rootfs")
    return pull_registry_image_to_store(image, image_store_dir=image_store_dir, platform=platform)


def image_dir_has_layers(image_path: Path) -> bool:
    img = read_image_metadata(image_path)
    return bool(img and img.get("layer_digests"))


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
