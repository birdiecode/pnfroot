from functools import wraps
import logging


logger = logging.getLogger("mycri")


def configure_logging(verbose=False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def log_rpc(method=None, *, request_log=True):
    def decorator(method):
        @wraps(method)
        async def wrapper(self, request, context):
            if request_log:
                request_text = str(request).strip() or "<empty request>"
                logger.info("%s.%s request:\n%s", self.__class__.__name__, method.__name__, request_text)
            return await method(self, request, context)

        return wrapper

    if method is None:
        return decorator
    return decorator(method)


def labels_match(labels, selector):
    for key, value in selector.items():
        if labels.get(key) != value:
            return False
    return True


def normalize_image_ref(image):
    if not image or "@" in image:
        return image

    name = image.rsplit("/", 1)[-1]
    if ":" in name:
        return image

    return f"{image}:latest"
