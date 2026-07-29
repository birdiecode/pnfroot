from virtual_paths import VirtualRoot


def test_virtual_root_renders_dns_override_resolv_conf(tmp_path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    root = VirtualRoot(str(rootfs), dns_servers=["8.8.8.8", "1.1.1.1"])

    assert root.virtual_generated_file_kind("/etc/resolv.conf") == "resolv.conf"
    assert root.render_resolv_conf() == "nameserver 8.8.8.8\nnameserver 1.1.1.1\n"


def test_virtual_root_uses_rootfs_resolv_conf_without_dns_override(tmp_path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    root = VirtualRoot(str(rootfs))

    assert root.virtual_generated_file_kind("/etc/resolv.conf") is None
