from __future__ import annotations

import argparse
import ipaddress
import struct
import unittest

import virtual_network
from virtual_network import (
    ContainerNetworkConfig,
    RTM_GETADDR,
    RTM_GETLINK,
    SIOCGIFTXQLEN,
    TrackedSocket,
    VirtualNetworkRuntime,
    build_rtnetlink_response,
    parse_netdev,
    parse_publish,
)
from ptrace_common import UserRegsStruct


class ParseNetdevTests(unittest.TestCase):
    def test_parse_minimal_interface(self) -> None:
        interface = parse_netdev("name=eth0,network=backend")

        self.assertEqual(interface.name, "eth0")
        self.assertEqual(interface.network, "backend")
        self.assertIsNone(interface.ip_address)
        self.assertIsNone(interface.prefix_length)
        self.assertEqual(interface.mtu, 1500)
        self.assertEqual(interface.dns_servers, [])

    def test_parse_full_interface(self) -> None:
        interface = parse_netdev(
            "name=eth0,network=backend,ip=10.20.0.15/24,"
            "gateway=10.20.0.1,mac=02:42:0a:14:00:0f,mtu=1450,"
            "dns=10.20.0.2;10.20.0.3"
        )

        self.assertEqual(interface.ip_address, "10.20.0.15")
        self.assertEqual(interface.prefix_length, 24)
        self.assertEqual(interface.gateway, "10.20.0.1")
        self.assertEqual(interface.mac_address, "02:42:0a:14:00:0f")
        self.assertEqual(interface.mtu, 1450)
        self.assertEqual(interface.dns_servers, ["10.20.0.2", "10.20.0.3"])

    def test_requires_name_and_network(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_netdev("name=eth0")
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_netdev("network=backend")


class ParsePublishTests(unittest.TestCase):
    def test_parse_host_and_container_port(self) -> None:
        published_port = parse_publish("18080:8080")

        self.assertEqual(published_port.host_ip, "127.0.0.1")
        self.assertEqual(published_port.host_port, 18080)
        self.assertEqual(published_port.container_port, 8080)
        self.assertEqual(published_port.protocol, "tcp")

    def test_parse_host_ip(self) -> None:
        published_port = parse_publish("0.0.0.0:18080:8080/tcp")

        self.assertEqual(published_port.host_ip, "0.0.0.0")
        self.assertEqual(published_port.host_port, 18080)
        self.assertEqual(published_port.container_port, 8080)

    def test_rejects_udp(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_publish("18080:8080/udp")


class RtnetlinkDumpTests(unittest.TestCase):
    def test_dump_contains_virtual_interface_and_address(self) -> None:
        interface = parse_netdev(
            "name=eth0,network=backend,ip=10.20.0.15/24,"
            "mac=02:42:0a:14:00:0f"
        )
        config = ContainerNetworkConfig(
            container_id="test",
            interfaces=[interface],
            service_socket="/tmp/net.unix",
        )
        request = netlink_request(RTM_GETLINK, 10) + netlink_request(RTM_GETADDR, 11)

        response = build_rtnetlink_response(request, config, port_id=12345)

        self.assertIn(b"eth0\x00", response)
        self.assertIn(bytes.fromhex("02420a14000f"), response)
        self.assertIn(ipaddress.IPv4Address("10.20.0.15").packed, response)
        self.assertNotIn(b"docker0\x00", response)
        self.assertEqual(struct.unpack_from("=I", response, 12)[0], 12345)

    def test_busybox_write_request_queues_virtual_rtnetlink_response(self) -> None:
        interface = parse_netdev("name=eth0,network=backend,ip=10.20.0.15/24")
        config = ContainerNetworkConfig(
            container_id="test",
            interfaces=[interface],
            service_socket="/tmp/net.unix",
        )
        runtime = VirtualNetworkRuntime(config)
        runtime.client = object()
        runtime.sockets.set(
            TrackedSocket(
                pid=123,
                fd=3,
                family=16,
                socket_type=3,
                protocol=0,
                netlink_port_id=123,
            )
        )
        request = netlink_request(RTM_GETLINK, 10, payload=b"\x00\x00\x00\x00")

        original_read_tracee_bytes = virtual_network.read_tracee_bytes
        original_set_regs = virtual_network.set_regs
        try:
            virtual_network.read_tracee_bytes = lambda pid, address, length: request
            virtual_network.set_regs = lambda pid, regs: None

            metadata = runtime.rewrite_syscall_entry(
                123,
                "write",
                [3, 0x1000, len(request)],
                UserRegsStruct(),
            )
        finally:
            virtual_network.read_tracee_bytes = original_read_tracee_bytes
            virtual_network.set_regs = original_set_regs

        tracked = runtime.sockets.get(123, 3)
        self.assertIsNotNone(tracked)
        assert tracked is not None
        self.assertEqual(metadata["network_forced_result"], len(request))
        self.assertTrue(tracked.netlink_queue)
        self.assertIn(b"eth0\x00", b"".join(tracked.netlink_queue))

    def test_ioctl_returns_tx_queue_length_for_virtual_interface(self) -> None:
        interface = parse_netdev("name=eth0,network=backend,ip=10.20.0.15/24")
        config = ContainerNetworkConfig(
            container_id="test",
            interfaces=[interface],
            service_socket="/tmp/net.unix",
        )
        runtime = VirtualNetworkRuntime(config)
        runtime.client = object()
        writes: dict[int, int] = {}

        original_read_tracee_bytes = virtual_network.read_tracee_bytes
        original_write_tracee_u32 = virtual_network.write_tracee_u32
        original_set_regs = virtual_network.set_regs
        try:
            virtual_network.read_tracee_bytes = (
                lambda pid, address, length: b"eth0\x00".ljust(length, b"\x00")
            )
            virtual_network.write_tracee_u32 = (
                lambda pid, address, value: writes.__setitem__(address, value)
            )
            virtual_network.set_regs = lambda pid, regs: None

            metadata = runtime.rewrite_syscall_entry(
                123,
                "ioctl",
                [3, SIOCGIFTXQLEN, 0x1000],
                UserRegsStruct(),
            )
        finally:
            virtual_network.read_tracee_bytes = original_read_tracee_bytes
            virtual_network.write_tracee_u32 = original_write_tracee_u32
            virtual_network.set_regs = original_set_regs

        self.assertEqual(metadata["network_forced_result"], 0)
        self.assertEqual(writes[0x1000 + 16], 1000)


def netlink_request(message_type: int, seq: int, payload: bytes = b"") -> bytes:
    length = 16 + len(payload)
    return struct.pack("=IHHII", length, message_type, 1, seq, 0) + payload


if __name__ == "__main__":
    unittest.main()
