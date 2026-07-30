#!/usr/bin/env python3
import argparse
import json
import logging
import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path


logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def normalize_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def safe_extract_layer(tar: tarfile.TarFile, rootfs: Path):
    rootfs = rootfs.resolve()

    for member in tar.getmembers():
        name = member.name.lstrip("./")
        target = (rootfs / name).resolve()

        if not str(target).startswith(str(rootfs)):
            raise RuntimeError(f"Небезопасный путь в tar: {member.name}")

        base = os.path.basename(name)
        parent = target.parent

        # Docker/OCI whiteout: удалить файл из нижнего слоя
        if base.startswith(".wh."):
            if base == ".wh..wh..opq":
                if parent.exists():
                    for child in parent.iterdir():
                        shutil.rmtree(child) if child.is_dir() else child.unlink(missing_ok=True)
            else:
                victim = parent / base[4:]
                if victim.is_dir():
                    shutil.rmtree(victim)
                else:
                    victim.unlink(missing_ok=True)
            continue

        tar.extract(member, rootfs, filter="fully_trusted")


def unpack_image(image_dir: str, rootfs_dir: str, clean: bool = False) -> Path:
    image_path = Path(image_dir)
    rootfs_path = Path(rootfs_dir)

    manifest_path = image_path / "manifest.json"
    layers_path = image_path / "layers"

    if not manifest_path.exists():
        raise FileNotFoundError(f"Не найден manifest.json: {manifest_path}")

    if not layers_path.exists():
        raise FileNotFoundError(f"Не найдена папка layers: {layers_path}")

    if clean and rootfs_path.exists():
        logger.info("Удаляю старый rootfs: %s", rootfs_path)
        shutil.rmtree(rootfs_path)

    rootfs_path.mkdir(parents=True, exist_ok=True)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    layers = manifest.get("layers", [])
    if not layers:
        raise RuntimeError("В manifest.json нет layers")

    for layer in layers:
        digest = layer["digest"]
        layer_file = layers_path / f"{digest.replace(':', '_')}.tar.gz"

        if not layer_file.exists():
            raise FileNotFoundError(f"Не найден слой: {layer_file}")

        logger.info("Распаковываю слой: %s", layer_file)

        with tarfile.open(layer_file, "r:*") as tar:
            safe_extract_layer(tar, rootfs_path)

    logger.info("Rootfs готов: %s", rootfs_path)
    return rootfs_path


def read_image_config(image_dir: str) -> dict:
    config_path = Path(image_dir) / "config.json"

    if not config_path.exists():
        return {
            "env": [],
            "workdir": "/",
            "user": None,
            "entrypoint": [],
            "cmd": ["/bin/sh"],
        }

    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cfg = data.get("config", {})

    return {
        "env": normalize_list(cfg.get("Env")),
        "workdir": cfg.get("WorkingDir") or "/",
        "user": cfg.get("User") or None,
        "entrypoint": normalize_list(cfg.get("Entrypoint")),
        "cmd": normalize_list(cfg.get("Cmd")),
    }


def build_container_command(
    image_dir: str,
    override_cmd: list[str] | None = None,
    override_entrypoint: list[str] | None = None,
):
    cfg = read_image_config(image_dir)

    entrypoint = cfg["entrypoint"]
    cmd = cfg["cmd"]

    if override_entrypoint is not None:
        entrypoint = override_entrypoint

    if override_cmd is not None:
        cmd = override_cmd

    command = entrypoint + cmd

    if not command:
        command = ["/bin/sh"]

    return command, cfg


def build_proot_command(
    proot_bin: str,
    rootfs_dir: str,
    image_cfg: dict,
    command: list[str],
    binds: list[str],
) -> list[str]:
    env = image_cfg.get("env") or []
    workdir = image_cfg.get("workdir") or "/"

    proot_cmd = [
        proot_bin,
        "-R", str(rootfs_dir),
        "-b", "/proc",
        "-b", "/sys",
        "-b", "/dev",
        "-b", "/tmp",
        "-w", workdir,
    ]

    for bind in binds:
        proot_cmd.extend(["-b", bind])

    proot_cmd.extend(command)

    if env:
        return ["env", *env, *proot_cmd]

    return proot_cmd


def print_command(cmd: list[str]):
    print()
    print("Команда для запуска:")
    print()
    print(" ".join(shlex.quote(x) for x in cmd))
    print()


def run_proot(cmd: list[str]):
    logger.info("Запускаю proot")
    subprocess.run(cmd, check=False)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("image_dir", help="Папка со скачанным образом")
    parser.add_argument("rootfs_dir", help="Куда распаковать rootfs")

    parser.add_argument("--clean", action="store_true", help="Удалить rootfs перед распаковкой")
    parser.add_argument("--run", action="store_true", help="Сразу запустить через proot")
    parser.add_argument("--proot", default="proot", help="Путь к proot, например ./tools/proot")

    parser.add_argument(
        "-b", "--bind",
        action="append",
        default=[],
        help="Дополнительный bind mount, например -b /host/path:/container/path",
    )

    parser.add_argument(
        "--entrypoint",
        nargs=argparse.REMAINDER,
        help="Заменить Entrypoint, например --entrypoint /bin/sh",
    )

    parser.add_argument(
        "--cmd",
        nargs=argparse.REMAINDER,
        help="Заменить только Cmd, например --cmd /bin/bash",
    )

    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    setup_logging(args.verbose)

    rootfs = unpack_image(
        image_dir=args.image_dir,
        rootfs_dir=args.rootfs_dir,
        clean=args.clean,
    )

    command, image_cfg = build_container_command(
        image_dir=args.image_dir,
        override_cmd=args.cmd,
        override_entrypoint=args.entrypoint,
    )

    proot_cmd = build_proot_command(
        proot_bin=args.proot,
        rootfs_dir=str(rootfs),
        image_cfg=image_cfg,
        command=command,
        binds=args.bind,
    )

    print_command(proot_cmd)

    if args.run:
        run_proot(proot_cmd)


if __name__ == "__main__":
    main()