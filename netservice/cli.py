#!/usr/bin/env python3
"""CLI for netservice runtime management."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys

SOCKET_DEFAULT = "/tmp/net.unix"


class Client:
    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._sock.connect(socket_path)
        except OSError as exc:
            self._sock.close()
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(1)
        self._reader = self._sock.makefile("rb")
        self._writer = self._sock.makefile("wb")

    def close(self) -> None:
        for f in (self._writer, self._reader, self._sock):
            try:
                f.close()
            except OSError:
                pass

    def request(self, msg: dict[str, object]) -> dict[str, object]:
        payload = json.dumps(msg, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self._writer.write(payload + b"\n")
        self._writer.flush()
        line = self._reader.readline()
        if not line:
            print("error: connection closed by server", file=sys.stderr)
            sys.exit(1)
        return json.loads(line.decode("utf-8"))


def do_publish_add(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        resp = c.request({
            "version": 1,
            "type": "publish_port",
            "container_id": args.container_id,
            "host_ip": args.host_ip,
            "host_port": args.host_port,
            "container_port": args.container_port,
            "protocol": args.protocol,
        })
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    print(f"published {args.host_ip}:{args.host_port} -> {args.container_id}:{args.container_port}")


def do_publish_remove(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        msg: dict[str, object] = {
            "version": 1,
            "type": "unpublish_port",
            "container_id": args.container_id,
        }
        if args.all:
            msg["all"] = True
        else:
            msg["host_ip"] = args.host_ip
            msg["host_port"] = args.host_port
            msg["protocol"] = args.protocol
        resp = c.request(msg)
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    print("ok")


def do_publish_list(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        resp = c.request({"version": 1, "type": "list_publishes"})
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    publishes = resp.get("publishes", [])
    if not publishes:
        print("no active publishes")
        return
    for p in publishes:
        print(f"{p['host_ip']}:{p['host_port']} -> {p['container_id']}:{p['container_port']}/{p['protocol']}")


def do_network_define(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        msg: dict[str, object] = {
            "version": 1,
            "type": "define_network",
            "name": args.name,
            "subnet": args.subnet,
        }
        if args.gateway:
            msg["gateway"] = args.gateway
        resp = c.request(msg)
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    parts = [f"defined network {args.name}", args.subnet]
    if args.gateway:
        parts.append(f"gateway {args.gateway}")
    print(" ".join(parts))


def do_network_remove(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        resp = c.request({
            "version": 1,
            "type": "remove_network",
            "name": args.name,
        })
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    print(f"removed network {args.name}")


def do_container_list(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        msg: dict[str, object] = {"version": 1, "type": "list_containers"}
        if args.network:
            msg["network"] = args.network
        resp = c.request(msg)
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    containers = resp.get("containers", [])
    if not containers:
        print("no containers")
        return
    for entry in containers:
        cid = entry["container_id"]
        for iface in entry["interfaces"]:
            print(f"{cid:20s} {iface['network']:15s} {iface['ip']}/{iface['prefix_length']}  {iface['name']}")


def do_network_list(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        resp = c.request({"version": 1, "type": "list_networks"})
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    networks = resp.get("networks", [])
    if not networks:
        print("no networks defined")
        return
    for n in networks:
        print(f"{n['name']:20s} {n['subnet']:18s} gateway {n['gateway']:15s} {n['allocated']} IP(s)")


def do_peer_add(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        resp = c.request({
            "version": 1,
            "type": "peer_networks",
            "source": args.source,
            "target": args.target,
        })
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    print(f"peered {args.source} -> {args.target}")


def do_peer_list(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        resp = c.request({"version": 1, "type": "list_peerings"})
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    peerings = resp.get("peerings", [])
    if not peerings:
        print("no peerings")
        return
    for p in peerings:
        print(f"{p['source']:20s} -> {p['target']}")


def do_peer_remove(args: argparse.Namespace) -> None:
    c = Client(args.socket)
    try:
        resp = c.request({
            "version": 1,
            "type": "unpeer_networks",
            "source": args.source,
            "target": args.target,
        })
    finally:
        c.close()
    if not resp.get("success"):
        print(f"error: {resp.get('error', 'unknown')}", file=sys.stderr)
        sys.exit(1)
    print(f"unpeered {args.source} -> {args.target}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage a running netservice instance.",
    )
    parser.add_argument(
        "-s",
        "--socket",
        default="/tmp/net.unix",
        help="Unix socket path (default: /tmp/net.unix)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # publish
    p_pub = sub.add_parser("publish", help="manage port publishing")
    p_pub_sub = p_pub.add_subparsers(dest="action", required=True)

    p_pub_add = p_pub_sub.add_parser("add", help="add a publish rule")
    p_pub_add.add_argument("container_id")
    p_pub_add.add_argument("--host-ip", default="127.0.0.1")
    p_pub_add.add_argument("--host-port", type=int, required=True)
    p_pub_add.add_argument("--container-port", type=int, required=True)
    p_pub_add.add_argument("--protocol", default="tcp")
    p_pub_add.set_defaults(func=do_publish_add)

    p_pub_rm = p_pub_sub.add_parser("remove", help="remove a publish rule")
    p_pub_rm.add_argument("container_id")
    p_pub_rm.add_argument("--host-ip", default="127.0.0.1")
    p_pub_rm.add_argument("--host-port", type=int)
    p_pub_rm.add_argument("--protocol", default="tcp")
    p_pub_rm.add_argument("--all", action="store_true", help="remove all rules for this container")
    p_pub_rm.set_defaults(func=do_publish_remove)

    p_pub_ls = p_pub_sub.add_parser("list", help="list active publishes")
    p_pub_ls.set_defaults(func=do_publish_list)

    # network
    p_net = sub.add_parser("network", help="manage virtual networks")
    p_net_sub = p_net.add_subparsers(dest="action", required=True)

    p_net_def = p_net_sub.add_parser("define", help="define a new network")
    p_net_def.add_argument("name")
    p_net_def.add_argument("--subnet", required=True)
    p_net_def.add_argument("--gateway")
    p_net_def.set_defaults(func=do_network_define)

    p_net_rm = p_net_sub.add_parser("remove", help="remove a network")
    p_net_rm.add_argument("name")
    p_net_rm.set_defaults(func=do_network_remove)

    p_net_ls = p_net_sub.add_parser("list", help="list networks")
    p_net_ls.set_defaults(func=do_network_list)

    # container
    p_ct = sub.add_parser("container", help="manage containers")
    p_ct_sub = p_ct.add_subparsers(dest="action", required=True)
    p_ct_ls = p_ct_sub.add_parser("list", help="list containers")
    p_ct_ls.add_argument("--network", help="filter by network name")
    p_ct_ls.set_defaults(func=do_container_list)

    # peer
    p_peer = sub.add_parser("peer", help="manage network peering")
    p_peer_sub = p_peer.add_subparsers(dest="action", required=True)

    p_peer_add = p_peer_sub.add_parser("add", help="peer source -> target")
    p_peer_add.add_argument("source")
    p_peer_add.add_argument("target")
    p_peer_add.set_defaults(func=do_peer_add)

    p_peer_ls = p_peer_sub.add_parser("list", help="list peerings")
    p_peer_ls.set_defaults(func=do_peer_list)

    p_peer_rm = p_peer_sub.add_parser("remove", help="remove peering")
    p_peer_rm.add_argument("source")
    p_peer_rm.add_argument("target")
    p_peer_rm.set_defaults(func=do_peer_remove)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
