from __future__ import annotations

import argparse
import ipaddress
import struct
import unittest

from virtual_network import (
    ContainerNetworkConfig,
    RTM_GETADDR,
    RTM_GETLINK,
    build_rtnetlink_response,
    parse_netdev,
)


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


def netlink_request(message_type: int, seq: int) -> bytes:
    return struct.pack("=IHHII", 16, message_type, 1, seq, 0)


if __name__ == "__main__":
    unittest.main()
