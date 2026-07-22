from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any

import grpc

from cri_common import log_rpc, logger, normalize_image_ref
from image_store import (
    IMAGE_PLATFORM,
    image_dir_name,
    path_size,
    pull_image_to_store,
    read_image_metadata,
    write_image_metadata,
)
import tools.api_pb2 as api_pb2
import tools.api_pb2_grpc as api_pb2_grpc


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

    def image_path(self, image_ref: str) -> Path:
        return self.image_store_dir / image_dir_name(image_ref)

    def normalize_repo_tags(self, img: dict[str, Any]) -> list[str]:
        repo_tags = img.get("repo_tags") or []
        if repo_tags:
            canonical = [tag for tag in repo_tags if isinstance(tag, str) and tag]
            if canonical:
                return [canonical[0]]
        image_id = img.get("image_id") or img.get("id") or "unknown:latest"
        return [str(image_id)]

    def load_images(self) -> None:
        for image_path in self.image_store_dir.iterdir():
            if not image_path.is_dir():
                continue
            img = read_image_metadata(image_path)
            if img is None or not img.get("layer_digests"):
                continue
            img["path"] = str(image_path)
            img["size"] = path_size(image_path)
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
            repo_tags = [img.get("id") or "unknown:latest"]
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
        except ValueError as exc:
            logger.debug("PullImage rejected %s: %s", image, exc)
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"pull image failed: {exc}")
        except Exception as exc:
            logger.exception("PullImage failed for %s", image)
            await context.abort(grpc.StatusCode.UNKNOWN, f"pull image failed: {exc}")

        repo_tags = [image_ref]
        img["repo_tags"] = repo_tags
        write_image_metadata(img)
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
        return api_pb2.ImageFsInfoResponse(image_filesystems=[api_pb2.FilesystemUsage(used_bytes=api_pb2.UInt64Value(value=path_size(self.image_store_dir)))])
