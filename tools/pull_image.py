#!/usr/bin/env python3
import argparse
import hashlib
import json
import logging
from pathlib import Path

import requests


REGISTRY = "https://registry-1.docker.io"
AUTH_URL = "https://auth.docker.io/token"

ACCEPT_MANIFEST = ", ".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
])


logger = logging.getLogger(__name__)


def parse_image(image: str):
    if "/" not in image:
        repo = f"library/{image}"
    else:
        repo = image

    if ":" in repo:
        repo, tag = repo.rsplit(":", 1)
    else:
        tag = "latest"

    return repo, tag


def get_token(repo: str) -> str:
    logger.info("Получаю token для repo=%s", repo)

    r = requests.get(
        AUTH_URL,
        params={
            "service": "registry.docker.io",
            "scope": f"repository:{repo}:pull",
        },
        timeout=30,
    )
    r.raise_for_status()

    return r.json()["token"]


def request_json(url: str, token: str):
    logger.debug("GET JSON: %s", url)

    r = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": ACCEPT_MANIFEST,
        },
        timeout=30,
    )
    r.raise_for_status()

    return r.json()


def download_blob(repo: str, digest: str, token: str, out_path: Path):
    if out_path.exists():
        logger.info("Файл уже существует: %s", out_path)
        return

    url = f"{REGISTRY}/v2/{repo}/blobs/{digest}"
    tmp_path = out_path.with_suffix(out_path.suffix + ".part")

    logger.info("Скачиваю blob: %s", digest)

    with requests.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        stream=True,
        timeout=60,
    ) as r:
        r.raise_for_status()

        h = hashlib.sha256()

        with open(tmp_path, "wb") as f:
            for chunk in r.iter_content(1024 * 1024):
                if not chunk:
                    continue

                f.write(chunk)
                h.update(chunk)

        real_digest = "sha256:" + h.hexdigest()

        if real_digest != digest:
            tmp_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"digest mismatch: expected {digest}, got {real_digest}"
            )

        tmp_path.rename(out_path)

    logger.info("Сохранено: %s", out_path)


def pull_image(
    image: str,
    output: str | None = None,
    platform: str = "linux/amd64",
) -> Path:
    """
    Скачивает Docker/OCI образ из Docker Hub.

    Результат:
        output/
        ├── manifest.json
        ├── config.json
        └── layers/
            ├── sha256_xxx.tar.gz
            └── sha256_yyy.tar.gz
    """

    repo, tag = parse_image(image)

    platform_os, platform_arch = platform.split("/", 1)

    out_dir = Path(output or image.replace("/", "_").replace(":", "_"))
    layers_dir = out_dir / "layers"

    out_dir.mkdir(parents=True, exist_ok=True)
    layers_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Образ: %s", image)
    logger.info("Repository: %s", repo)
    logger.info("Tag: %s", tag)
    logger.info("Platform: %s", platform)
    logger.info("Output: %s", out_dir)

    token = get_token(repo)

    manifest_url = f"{REGISTRY}/v2/{repo}/manifests/{tag}"
    manifest = request_json(manifest_url, token)

    media_type = manifest.get("mediaType", "")

    if "manifest.list" in media_type or "image.index" in media_type:
        logger.info("Образ мультиплатформенный, ищу platform=%s", platform)

        selected = None

        for item in manifest["manifests"]:
            p = item.get("platform", {})

            if (
                p.get("os") == platform_os
                and p.get("architecture") == platform_arch
            ):
                selected = item
                break

        if not selected:
            raise RuntimeError(f"platform not found: {platform}")

        digest = selected["digest"]

        logger.info("Выбран manifest digest: %s", digest)

        index_path = out_dir / "index.json"
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)

        logger.info("Сохранён index.json: %s", index_path)

        manifest_url = f"{REGISTRY}/v2/{repo}/manifests/{digest}"
        manifest = request_json(manifest_url, token)

    manifest_path = out_dir / "manifest.json"

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    logger.info("Сохранён manifest.json: %s", manifest_path)

    config_digest = manifest["config"]["digest"]
    config_path = out_dir / "config.json"

    download_blob(repo, config_digest, token, config_path)

    for layer in manifest["layers"]:
        digest = layer["digest"]
        filename = digest.replace(":", "_") + ".tar.gz"
        layer_path = layers_dir / filename

        download_blob(repo, digest, token, layer_path)

    logger.info("Готово: %s", out_dir)

    return out_dir


def setup_logging(verbose: bool = False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image", help="например: alpine:latest, ubuntu:24.04")
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("--platform", default="linux/amd64")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    setup_logging(args.verbose)

    pull_image(
        image=args.image,
        output=args.output,
        platform=args.platform,
    )


if __name__ == "__main__":
    main()