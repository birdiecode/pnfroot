# Virtual networking prototype

This project does not create Linux network namespaces or host interfaces. The
container network exists in the ptrace runtime and in the external Unix-socket
network service.

## Runtime options

Start the service:

```bash
python3 -m netservice.server --socket /tmp/net.unix
```

Add `--log` or `--verbose` to print service registration, bind, and connect
decisions.

Allow selected logical networks to reach non-virtual IP destinations through the
host network:

```bash
python3 -m netservice.server \
  --socket /tmp/net.unix \
  --internet-networks backend,frontend
```

`--internet-networks` may be repeated. The service still keeps virtual
same-network addresses under the registry: an unregistered address inside the
virtual subnet is denied instead of being treated as internet egress.

Run a container with one virtual interface:

```bash
./ptrace_syscalls.py \
  --container-id app-01 \
  --rootfs ./app_rootfs \
  --netdev 'name=eth0,network=backend,ip=10.20.0.10/24,gateway=10.20.0.1' \
  --netservice /tmp/net.unix \
  -- ./app
```

The runtime is quiet by default. Add `--log` or `--verbose` to print traced
syscalls. Use service-side `--log` to see route, bind, proxy, and deny decisions.
The old `--quiet` option is accepted for compatibility, but quiet mode is
already the default.

Run a second container on the same logical network:

```bash
./ptrace_syscalls.py \
  --container-id db-01 \
  --rootfs ./db_rootfs \
  --netdev 'name=eth0,network=backend,ip=10.20.0.20/24,gateway=10.20.0.1' \
  --netservice /tmp/net.unix \
  -- ./database
```

If `ip` is omitted, the service assigns an IPv4 address from a deterministic
per-network `/24` subnet:

```bash
./ptrace_syscalls.py \
  --container-id test-client \
  --rootfs ./ubuntu_c \
  --netdev 'name=eth0,network=testnet' \
  --netservice /tmp/net.unix \
  -- curl http://10.50.0.20:8080
```

`--netdev` accepts these fields:

```text
name      required interface name visible to the virtual runtime
network   required logical network name
ip        optional address, with optional prefix, for example 10.20.0.15/24
gateway   optional virtual gateway
mac       optional virtual MAC address
mtu       optional MTU, default 1500
dns       optional DNS server; repeat the field or separate values with semicolon
```

`--netdev` requires `--netservice`. `--container-id` is optional; if omitted the
runtime generates an id like `container-8f42c7`.

Multiple `--netdev` arguments are parsed and registered. The first prototype
routes IPv4 TCP through the first interface whose prefix contains the
destination, otherwise through the first configured interface.

## Protocol

The runtime connects to `--netservice` over a Unix stream socket. Messages are
newline-terminated JSON objects with `version: 1`.

Registration:

```json
{"version":1,"type":"register_container","container_id":"app-01","pid":15432,"interfaces":[{"name":"eth0","network":"backend","ip":"10.20.0.10","prefix_length":24,"gateway":"10.20.0.1","mac":null,"mtu":1500,"dns":[]}]}
```

Connect request:

```json
{"version":1,"type":"connect_request","request_id":"req-7ab18f","container_id":"app-01","pid":15432,"tid":15435,"fd":7,"protocol":"tcp","address_family":"ipv4","source":{"interface":"eth0","network":"backend","ip":"10.20.0.10","port":0},"destination":{"ip":"10.20.0.20","port":5432}}
```

The service returns `allow`, `deny`, `redirect`, or `proxy`. The bundled service
returns `proxy` for registered virtual ports:

```json
{"version":1,"type":"connect_result","request_id":"req-7ab18f","action":"proxy","connection_id":"conn-f14c23","proxy":{"ip":"127.0.0.1","port":18080}}
```

Bind request:

```json
{"version":1,"type":"bind_request","request_id":"req-b18c21","container_id":"db-01","pid":15432,"fd":5,"protocol":"tcp","interface":"eth0","network":"backend","virtual_address":{"ip":"10.20.0.20","port":5432}}
```

The service returns a loopback address. The runtime rewrites `sockaddr_in`
before the kernel sees `bind(2)`:

```json
{"version":1,"type":"bind_result","request_id":"req-b18c21","action":"redirect","real_address":{"ip":"127.0.0.1","port":31245}}
```

Unregistration:

```json
{"version":1,"type":"unregister_container","container_id":"app-01"}
```

## Current behavior

The runtime tracks `socket`, `connect`, `bind`, `accept`, `accept4`, `close`,
`dup`, `dup2`, `dup3`, `close_range`, `getsockname`, `getpeername`, `sendto`,
`sendmsg`, and `recvmsg`.

For `NETLINK_ROUTE` sockets, the runtime emulates the minimal rtnetlink dump
used by `ip a`: `RTM_GETLINK` and `RTM_GETADDR` return `lo` plus the configured
virtual interfaces. Host interfaces are not included in that dump.

The first working path is IPv4 TCP:

1. A server process calls `bind(10.20.0.20:8080)`.
2. The runtime asks the service for a real loopback bind address.
3. The service stores `backend / 10.20.0.20:8080 -> 127.0.0.1:PORT`.
4. A client process calls `connect(10.20.0.20:8080)`.
5. The runtime asks the service for a route.
6. The service creates a one-shot TCP proxy and returns its loopback address.
7. The runtime rewrites the client's `sockaddr_in` to the proxy address.

## Limitations

The prototype is intentionally minimal:

* IPv4 TCP is implemented; IPv6 routing currently returns `EAFNOSUPPORT`.
* UDP is not implemented.
* Internet egress is opt-in per logical network via service-side
  `--internet-networks`. Without it, a connection such as `curl 8.8.8.8` is
  denied unless that destination is represented by a registered virtual
  container port and route.
* There is no virtual DNS proxy yet.
* Minimal rtnetlink interface discovery for `ip a` is implemented. Broader
  netlink families/messages, `ioctl(SIOCGIF*)`, `/proc/net/*`, and
  `/sys/class/net` are not fully emulated yet.
* The service allows traffic within the same logical network and denies direct
  cross-network routing.
* `bind` registration is optimistic: if the traced process later fails the real
  kernel bind, the service keeps the mapping until container unregister.
* The TCP proxy is one-shot per `connect_request`.
