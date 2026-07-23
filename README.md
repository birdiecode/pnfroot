# pnfroot

`pnfroot` - экспериментальный rootless container runtime для Linux с частичной
реализацией Kubernetes CRI. Проект запускает контейнерные процессы без
privileged-демона и использует `ptrace` для виртуализации части системных
вызовов, файловой системы, идентификаторов и сетевого поведения.

Проект не является production-ready заменой `containerd`, CRI-O или Docker. Его
цель - исследование rootless-модели исполнения и совместимости с CRI.

## Возможности

- CRI gRPC server на Unix socket.
- `ImageService`: `ListImages`, `ImageStatus`, `PullImage`, `RemoveImage`,
  `ImageFsInfo`, `StreamImages`.
- `RuntimeService`: sandbox/container lifecycle, `ExecSync`, streaming `Exec`.
- Registry pull через Docker Registry v2 для обычных образов вроде `busybox`.
- Content-store образов: manifest/config/layer blobs хранятся отдельно от rootfs
  контейнеров.
- Распаковка rootfs в `containers/<container-id>/rootfs`.
- Сохранение pod/container state между перезапусками сервиса.
- HTTP streaming server для CRI Exec с WebSocket и SPDY transport.
- Прямой запуск контейнеризации через `ptrace_syscalls.run_tracee`, без запуска
  `ptrace_syscalls.py` как subprocess-обертки.
- Виртуальная сеть через `virtual_network.py` и `netservice`.

## Реализованные CRI вызовы

Сейчас реализованы и проверены следующие CRI вызовы:

- `RunPodSandbox`
- `PullImage`
- `CreateContainer`
- `StartContainer`
- `ContainerStatus`
- `StopContainer`
- `RemoveContainer`
- `StopPodSandbox`
- `RemovePodSandbox`

## Структура

```text
pnfroot.py          CRI RuntimeService, lifecycle контейнеров, запуск процессов
image_service.py    CRI ImageService
image_store.py      pull/store/unpack образов, OCI/Docker blobs
streaming.py        HTTP/WebSocket/SPDY transport для Exec
ptrace_syscalls.py  ptrace-based execution engine
virtual_paths.py    виртуальный rootfs, bind mounts, path translation
virtual_ids.py      виртуальные uid/gid/pid значения
virtual_network.py  виртуальная сеть внутри traced-процессов
netservice/         Unix-socket сетевой сервис и TCP forwarding
tools/              CRI protobuf и локальный crictl
tests/              unit/integration tests
```

## Хранилища

По умолчанию runtime использует:

```text
/tmp/pnfroot/images
/tmp/pnfroot/containers
```

`image-store` хранит только content-store образов:

```text
images/<image-ref>/
  pnfroot-image.json
  blobs/sha256/<digest>
```

Распакованные rootfs лежат отдельно:

```text
containers/<container-id>/rootfs/
```

Состояние CRI runtime сохраняется здесь:

```text
containers/pnfroot-runtime-state.json
```

После перезапуска сервиса pod и container metadata загружаются обратно.
Контейнеры, которые были `Running`, восстанавливаются как `Exited`: процесс
нельзя безопасно переподключить к новому Python-сервису после его рестарта.

## Запуск CRI сервера

```bash
cd /home/birdiecode/Documents/tk8s/pnfroot
. .venv/bin/activate

python pnfroot.py \
  --socket-path /tmp/pnfroot.sock \
  --image-store-dir /tmp/pnfroot/images \
  --container-store-dir /tmp/pnfroot/containers
```

С pod-сетью через `network_service`:

```bash
python pnfroot.py \
  --socket-path /tmp/pnfroot.sock \
  --image-store-dir /tmp/pnfroot/images \
  --container-store-dir /tmp/pnfroot/containers \
  --netservice-socket /tmp/net.unix \
  --pod-network podnet
```

Streaming-сервер для `Exec` по умолчанию слушает `127.0.0.1` на случайном порту
и возвращает CRI URL вида:

```text
http://127.0.0.1:<port>/exec/<token>
```

Порт можно зафиксировать через `--stream-port`, а host в URL переопределить
через `--stream-public-host`.

## Проверка через crictl

```bash
POD=$(./tools/crictl runp ./tests/test_pod.json)
CON=$(./tools/crictl create "$POD" ./tests/test_container.json ./tests/test_pod.json)

./tools/crictl start "$CON"
./tools/crictl ps -a
./tools/crictl exec -it "$CON" /bin/sh
```

Если нужен явный WebSocket transport:

```bash
./tools/crictl exec --transport websocket -it "$CON" /bin/sh
```

## Pull образа

Registry image:

```bash
./tools/crictl pull busybox
```

CRI `PullImage` не принимает локальный rootfs-каталог как image source. Для
локального rootfs используйте прямой режим `ptrace_syscalls.py --rootfs`.

## Ptrace runner

Процесс можно запускать напрямую под tracer без CRI:

```bash
./ptrace_syscalls.py -- /bin/ls -la
./ptrace_syscalls.py --rootfs ./ubuntu_c -- /bin/bash
./ptrace_syscalls.py --rootfs ./ubuntu_c --uid 0 --gid 0 -- /bin/bash
./ptrace_syscalls.py --rootfs ./ubuntu_c --bind /tmp:/host-tmp -- /bin/ls /host-tmp
```

## Виртуальная сеть

Сначала запускается сетевой сервис:

```bash
python3 -m netservice.server \
  --socket /tmp/net.unix \
  --network podnet=10.42.0.0/24 \
  --internet-networks podnet \
  --log
```

`--network` задает имя сети и CIDR, из которого `network_service` раздает Pod IP.
Контейнеры внутри одного Pod используют общий virtual loopback, поэтому могут
ходить друг к другу через `127.0.0.1`. Разные Pod в одной сети могут обращаться
друг к другу напрямую по Pod IP без NAT.

Затем traced-процесс можно запустить с виртуальным интерфейсом:

```bash
./ptrace_syscalls.py \
  --netdev name=eth0,network=podnet \
  --netservice /tmp/net.unix \
  -- /bin/bash
```

## Тесты

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover -s tests
git diff --check
```

## Ограничения

- CRI покрыт частично.
- Изоляция построена на ptrace-перехвате, а не на полноценной комбинации Linux
  namespaces/cgroups.
- После рестарта сервиса процессы не reattach-ятся, только metadata состояния
  сохраняется.
- Совместимость с образами и системными вызовами расширяется постепенно.
- Runtime предназначен для экспериментов, тестов и прототипирования.
