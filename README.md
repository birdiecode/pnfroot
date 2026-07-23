# pnfroot

`pnfroot` - экспериментальный rootless container runtime для Linux с частичной
реализацией Kubernetes CRI v1. Проект запускает контейнерные процессы без
privileged-демона и использует `ptrace` для виртуализации части системных
вызовов, файловой системы, идентификаторов и сетевого поведения.

Проект не является production-ready заменой `containerd`, CRI-O или Docker. Его
цель - исследование rootless-модели исполнения и совместимости с CRI.

## Возможности

- CRI gRPC server на Unix socket.
- `ImageService`: pull/list/status/remove/images filesystem info.
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

## Quickstart

Quickstart рассчитан на Linux, Python `>=3.10`, доступ к Docker Hub и bundled
`./tools/crictl` из репозитория. Pod/container config лежит в
`tests/fixtures/quickstart_pod.json` и
`tests/fixtures/quickstart_container.json`.

```bash
cd /path/to/pnfroot
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Поднимите CRI server и запустите container:

```bash
set -euo pipefail

export PNFROOT_QS=/tmp/pnfroot-quickstart
export PNFROOT_SOCK="$PNFROOT_QS/pnfroot.sock"

rm -rf "$PNFROOT_QS"
mkdir -p "$PNFROOT_QS"

python pnfroot.py \
  --socket-path "$PNFROOT_SOCK" \
  --image-store-dir "$PNFROOT_QS/images" \
  --container-store-dir "$PNFROOT_QS/containers" \
  --stream-port 18080

CRICTL=(
  ./tools/crictl
  --config /dev/null
  --runtime-endpoint "unix://$PNFROOT_SOCK"
  --image-endpoint "unix://$PNFROOT_SOCK"
  --timeout 30s
)

"${CRICTL[@]}" version
"${CRICTL[@]}" pull busybox:1.38.0

POD=$("${CRICTL[@]}" runp tests/fixtures/quickstart_pod.json)
CON=$(
  "${CRICTL[@]}" create \
    "$POD" \
    tests/fixtures/quickstart_container.json \
    tests/fixtures/quickstart_pod.json
)

"${CRICTL[@]}" start "$CON"
"${CRICTL[@]}" ps -a
```

Получите stdout log контейнера:

```bash
"${CRICTL[@]}" logs "$CON"
```

Ожидаемый log содержит строку `quickstart-ready`.

Выполните команду внутри контейнера через streaming `Exec`:

```bash
"${CRICTL[@]}" exec --transport websocket "$CON" /bin/sh -c 'echo quickstart-exec'
```

## Поддерживаемые CRI RPC

Все остальные `RuntimeService` RPC из `tools/api.proto` используют default
servicer из сгенерированного gRPC-кода и возвращают `UNIMPLEMENTED`.

| Service | RPC | Status | Scope |
| --- | --- | --- | --- |
| `RuntimeService` | `Version` | Supported | Возвращает `pnfroot` и версию `0.1.0`. |
| `RuntimeService` | `Status` | Supported | Возвращает `RuntimeReady` и `NetworkReady`. |
| `RuntimeService` | `RuntimeConfig` | Supported | Возвращает Linux runtime config с `cgroupfs`. |
| `RuntimeService` | `RunPodSandbox` | Supported | Создает sandbox metadata/state; при настройке `netservice` выделяет virtual Pod IP. |
| `RuntimeService` | `StopPodSandbox` | Supported | Останавливает процессы контейнеров в sandbox и переводит sandbox в `SANDBOX_NOTREADY`. |
| `RuntimeService` | `RemovePodSandbox` | Supported | Удаляет sandbox metadata и освобождает virtual network allocation. |
| `RuntimeService` | `PodSandboxStatus` | Supported | Возвращает metadata/state/network status. |
| `RuntimeService` | `ListPodSandbox` | Supported | Поддерживает фильтры по id, state и labels. |
| `RuntimeService` | `CreateContainer` | Supported | Создает container metadata, сохраняет state, асинхронно готовит rootfs. |
| `RuntimeService` | `StartContainer` | Supported | Запускает процесс контейнера через host subprocess или ptrace-backed execution. |
| `RuntimeService` | `StopContainer` | Supported | Завершает процесс, соблюдая timeout до принудительного kill. |
| `RuntimeService` | `RemoveContainer` | Supported | Останавливает процесс при необходимости и удаляет bundle/rootfs. |
| `RuntimeService` | `ListContainers` | Supported | Поддерживает фильтры по id, pod sandbox id, state и labels. |
| `RuntimeService` | `ContainerStatus` | Supported | Возвращает lifecycle status, timestamps, image refs, log path и Linux user info. |
| `RuntimeService` | `ExecSync` | Supported | Запускает команду и возвращает stdout/stderr/exit code; timeout дает exit code `124`. |
| `RuntimeService` | `Exec` | Supported | Возвращает CRI streaming URL; WebSocket и SPDY transport обслуживаются streaming server. |
| `ImageService` | `ListImages` | Supported | Возвращает image store content с фильтром по image spec. |
| `ImageService` | `StreamImages` | Supported | Отдает один stream response с текущим списком images. |
| `ImageService` | `ImageStatus` | Supported | Возвращает image metadata или пустой status. |
| `ImageService` | `PullImage` | Supported | Тянет registry image через Docker Registry v2; локальные rootfs sources отклоняются. |
| `ImageService` | `RemoveImage` | Supported | Удаляет image content из local image store. |
| `ImageService` | `ImageFsInfo` | Supported | Возвращает размер local image store. |

## Архитектура

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

`pnfroot.py` поднимает один async gRPC server на Unix socket и регистрирует
`RuntimeService` и `ImageService`. Runtime state хранится в JSON под
`container-store-dir`, поэтому metadata pod/container переживает рестарт
сервиса.

`image_store.py` реализует простой OCI/Docker content-store: manifest, config и
layers сохраняются как blobs, а rootfs контейнера распаковывается отдельно в
bundle конкретного container id. Pull выполняется напрямую через Docker Registry
v2 API.

Для запуска процесса runtime выбирает самый простой доступный путь. Если не
нужны rootfs/user/network virtualization, используется обычный host subprocess.
Если нужна контейнеризация, запускается supervisor-процесс и
`ptrace_syscalls.run_tracee`, который переписывает выбранные syscall-аргументы и
возвращаемые значения.

Streaming `Exec` отделен от gRPC API: CRI `Exec` выдает URL, а `streaming.py`
обслуживает WebSocket/SPDY remote-command протокол и подключает его к процессу,
запущенному runtime.

Виртуальная сеть вынесена в `netservice`: runtime выделяет Pod IP через Unix
socket, traced-процессы получают виртуальные интерфейсы, а TCP forwarding
проксирует соединения между virtual endpoints и host sockets.

## Модель безопасности

`pnfroot` не запускает privileged daemon и не требует root для базового
запуска. Все файлы, процессы, registry blobs и sockets создаются с правами того
пользователя, который запустил runtime.

Изоляция является ptrace-based virtualization layer, а не kernel-enforced
container sandbox. Процессы не помещаются в полноценный набор namespaces/cgroups,
а syscall coverage ограничен реализованными перехватчиками. Это полезно для
исследования совместимости CRI и rootless execution, но не является надежной
границей безопасности для недоверенного кода.

Виртуальные uid/gid/pid, filesystem path translation и virtual network state
предназначены для совместимости поведения внутри traced-процесса. Они не
заменяют seccomp, LSM-политики, user namespaces, mount namespaces, network
namespaces или cgroup enforcement.

Образы скачиваются и распаковываются локально без signature verification и без
политик допуска. Запускайте только те образы и команды, которым доверяете.

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

## Ручной запуск CRI сервера

```bash
cd /path/to/pnfroot
. .venv/bin/activate

python pnfroot.py \
  --socket-path /tmp/pnfroot.sock \
  --image-store-dir /tmp/pnfroot/images \
  --container-store-dir /tmp/pnfroot/containers
```

С pod-сетью через `netservice`:

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

## Pull образа

Registry image:

```bash
./tools/crictl \
  --runtime-endpoint unix:///tmp/pnfroot.sock \
  --image-endpoint unix:///tmp/pnfroot.sock \
  pull busybox:1.38.0
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

`--network` задает имя сети и CIDR, из которого `netservice` раздает Pod IP.
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

- Linux-only; Windows/macOS не поддерживаются.
- CRI покрыт частично; Kubernetes node conformance не является целью `v0.1.0`.
- Изоляция построена на ptrace-перехвате, а не на полноценной комбинации Linux
  namespaces/cgroups/seccomp/LSM.
- Syscall virtualization покрывает только реализованные пути; неизвестные или
  новые syscall-паттерны могут вести себя как host process.
- Нет cgroup accounting/enforcement, container stats, pod stats, metrics,
  checkpoint/restore, attach и port-forward.
- После рестарта сервиса процессы не reattach-ятся, только metadata состояния
  сохраняется.
- Registry support минимальный: Docker Registry v2 pull, без credential helpers,
  mirror policy, signature verification и admission policy.
- Runtime предназначен для экспериментов, тестов и прототипирования, а не для
  запуска недоверенных workload.
