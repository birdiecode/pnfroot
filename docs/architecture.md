# Архитектура pnfroot

## Общая структура проекта

```mermaid
graph TB
    subgraph "gRPC API (CRI-O compatible)"
        API["tools/api.proto<br/>RuntimeService + ImageService"]
    end

    subgraph "Основной процесс"
        PNF["pnfroot.py<br/>RuntimeService<br/>gRPC сервер"]
        IMG_SVC["image_service.py<br/>ImageService"]
        STREAM["streaming.py<br/>Exec/Attach"]
    end

    subgraph "Виртуализация (ptrace)"
        PTRACE["ptrace_syscalls.py<br/>syscall tracer"]
        VPATHS["virtual_paths.py<br/>VirtualRoot"]
        VIDS["virtual_ids.py<br/>VirtualIds"]
        VNET["virtual_network.py<br/>VirtualNetworkRuntime"]
        PTRACE --> VPATHS
        PTRACE --> VIDS
        PTRACE --> VNET
    end

    subgraph "Network service"
        NS["netservice/"]
    end

    subgraph "Хранилище образов"
        ISTORE["image_store.py<br/>RegistryClient + pull/unpack"]
    end

    subgraph "Общие модули"
        COMMON["cri_common.py<br/>logging, helpers"]
        PCOMMON["ptrace_common.py<br/>ptrace wrappers, SyscallContext"]
    end

    PNF --> PTRACE
    PNF --> IMG_SVC
    PNF --> STREAM
    PNF --> COMMON
    PNF --> VNET
    IMG_SVC --> ISTORE
    IMG_SVC --> COMMON
    STREAM --> COMMON
    ISTORE --> COMMON
    VNET --> NS
    VNET --> PCOMMON
    VPATHS --> PCOMMON
    VIDS --> PCOMMON
    PNF -.-> API
    IMG_SVC -.-> API
    PNF --> PCOMMON
```

## Модули и их ответственность

| Модуль | Строк | Назначение |
|---|---|---|
| `pnfroot.py` | 1680 | CRI runtime сервер: gRPC RuntimeService, жизненный цикл контейнеров, запуск процессов, сохранение состояния |
| `ptrace_syscalls.py` | 769 | Ptrace-движок: форк tracee, перехват syscall enter/exit, диспетчеризация в модули виртуализации |
| `ptrace_common.py` | 378 | Примитивы ptrace: обёртки ptrace, чтение/запись регистров и памяти tracee, таблицы имён syscall |
| `virtual_paths.py` | 1125 | Виртуальная корневая ФС: подмена путей, bind mount, виртуализация mount(2), ELF interpreter |
| `virtual_ids.py` | 555 | Виртуальные uid/gid: per-pid credentials, перехват get*id/set*id/chown |
| `virtual_network.py` | 1748 | Виртуальная сеть: отслеживание сокетов, rtnetlink, виртуализация connect/bind через netservice |
| `cri_common.py` | 46 | Общие утилиты CRI: настройка логов, декоратор RPC, метки, нормализация image ref |
| `image_service.py` | 166 | CRI ImageService gRPC: list/pull/status/remove образов |
| `image_store.py` | 414 | OCI/Docker registry клиент: pull/manifest/config/layers, извлечение в rootfs |
| `streaming.py` | 824 | CRI Exec сервер: HTTP+WebSocket+SPDY/3.1 transport, stdin/stdout/stderr/resize |
| `netservice/` | 1410 | Unix-socket сетевой сервис: управление IP, проброс портов, маршрутизация, TCP-proxy |

---

## gRPC API

```mermaid
graph LR
    subgraph "RuntimeService"
        RV["Version"]
        RS["Status"]
        RC["RuntimeConfig"]
        RPS["RunPodSandbox"]
        SPS["StopPodSandbox"]
        RMPS["RemovePodSandbox"]
        PSS["PodSandboxStatus"]
        LPS["ListPodSandbox"]
        CC["CreateContainer"]
        SC["StartContainer"]
        STC["StopContainer"]
        RMC["RemoveContainer"]
        LC["ListContainers"]
        CS["ContainerStatus"]
        ES["ExecSync"]
        E["Exec"]
    end

    subgraph "ImageService"
        LI["ListImages"]
        SI["StreamImages"]
        IS["ImageStatus"]
        PI["PullImage"]
        RI["RemoveImage"]
        IFI["ImageFsInfo"]
    end

    subgraph "Статус"
        IMPL["✅ Реализовано"]
        UNIMPL["❌ Не реализовано"]
    end

    RV --> IMPL
    RS --> IMPL
    RC --> IMPL
    RPS --> IMPL
    SPS --> IMPL
    RMPS --> IMPL
    PSS --> IMPL
    LPS --> IMPL
    CC --> IMPL
    SC --> IMPL
    STC --> IMPL
    RMC --> IMPL
    LC --> IMPL
    CS --> IMPL
    ES --> IMPL
    E --> IMPL
    LI --> IMPL
    SI --> IMPL
    IS --> IMPL
    PI --> IMPL
    RI --> IMPL
    IFI --> IMPL
```

---

## Жизненный цикл Pod / Container

```mermaid
sequenceDiagram
    participant C as CRI-клиент (crictl, kubelet)
    participant P as pnfroot (RuntimeService)
    participant PT as ptrace_syscalls
    participant ST as image_store
    participant NS as netservice (опционально)

    C->>P: RunPodSandbox
    alt Pod networking enabled
        P->>NS: allocate_container(pod_id)
        NS-->>P: IP 10.88.0.2/24
    end
    P-->>C: PodSandboxID

    C->>P: CreateContainer
    P->>P: prepare_container_rootfs_async()
    Note over P: асинхронно: pull образа + распаковка в rootfs
    P-->>C: ContainerID

    C->>P: StartContainer
    P->>P: wait_for_container_rootfs()
    ST-->>P: rootfs готов
    alt Есть сетевые интерфейсы
        P->>PT: run_tracee()
        PT->>PT: fork + ptrace
        PT->>NS: register_container(pid, interfaces, publish)
        NS-->>PT: IPs + gateway
        PT->>PT: rewrite syscalls
    else Хост-процесс
        P->>P: start_host_process()
    end
    P-->>C: OK

    C->>P: StopContainer
    P->>PT: process.terminate()
    P-->>C: OK

    C->>P: RemovePodSandbox
    alt Pod networking enabled
        P->>NS: release_container(pod_id)
    end
    P-->>C: OK
```

---

## Перехват системных вызовов (ptrace)

```mermaid
flowchart TB
    START["trace() — главный цикл"] --> WAIT["waitpid() — ждём останов tracee"]
    WAIT --> CHECK{"PTRACE_EVENT_*?"}

    CHECK -- "PTRACE_EVENT_SECCOMP" --> ENTER["syscall_entry(pid)"]
    CHECK -- "PTRACE_EVENT_CLONE/FORK/VFORK/EXEC" --> EVENT["handle event (clone/fork/vfork/exec)"]
    CHECK -- "другое" --> OTHER["обработка сигнала"]

    ENTER --> DISPATCH["dispatch_syscall_handlers(context)"]
    DISPATCH --> VIRT["Модули виртуализации:"]
    
    VIRT --> VNET_ENTER["VirtualNetworkRuntime<br/>rewrite_syscall_entry()"]
    VIRT --> VPATHS_ENTER["VirtualRoot<br/>rewrite_syscall_entry()"]
    VIRT --> VIDS_ENTER["VirtualIds<br/>neutralize_syscall()"]

    VNET_ENTER --> DONE{"rewrite?"}
    VPATHS_ENTER --> DONE
    VIDS_ENTER --> DONE

    DONE -- "да" --> POKE["ptrace_poke() — подмена аргументов в памяти tracee"]
    DONE -- "нет" --> SKIP

    POKE --> SKIP["set_regs() — возобновление"]
    SKIP --> RESUME["resume_syscall(pid)"]
    RESUME --> WAIT

    WAIT --> EXIT_CHECK{"это выход из syscall?"}
    EXIT_CHECK -- "да" --> EXIT["syscall_exit(pid, record)"]
    EXIT --> DISPATCH_EXIT["dispatch_syscall_handlers(context)"]
    DISPATCH_EXIT --> VIRT_EXIT["handlers возвращают sockaddr data для нейтрализации"]
    VIRT_EXIT --> NEUTRALIZE["neutralize_syscall() или restore_sockaddr_if_needed()"]
    NEUTRALIZE --> RESUME
    EXIT_CHECK -- "нет" --> CHECK
```

---

## Виртуальная корневая ФС

```mermaid
flowchart LR
    subgraph "Tracee видит"
        APP["Приложение"] --> SYS["open(/etc/passwd)<br/>stat(/usr/bin/python)<br/>readlink(/proc/self/exe)"]
    end

    subgraph "VirtualRoot (virtual_paths.py)"
        REWRITE["rewrite_syscall_entry()"]
        REWRITE --> HOST["host_path() — подмена пути"]
        REWRITE --> MOUNT["neutralize_mount() — виртуализация mount(2)"]
        REWRITE --> EXEC["prepare_dynamic_exec() — ELF interpreter"]
        EXIT["handle_syscall_exit()"]
        EXIT --> GETCWD["rewrite_getcwd_result()"]
        EXIT --> MOUNT_EXIT["apply_mount() — bind mount на хосте"]
    end

    subgraph "Хостовая ФС"
        ROOTFS["rootfs/ — корень tracee"]
        BINDS["bind mounts — проброс каталогов"]
    end

    SYS --> REWRITE
    HOST --> ROOTFS
    HOST --> BINDS
```

---

## Виртуальные uid/gid

```mermaid
flowchart LR
    subgraph "Tracee"
        TASK["Процесс tracee"] --> ID_SYSCALL["getuid() → 0<br/>setuid(1000) → OK<br/>chown(file, 1000) → OK"]
    end

    subgraph "VirtualIds (virtual_ids.py)"
        VIRT["VirtualIds"]
        VIRT --> CRED["VirtualCredentials<br/>ruid/euid/suid/fsuid<br/>rgid/egid/sgid/fsgid"]
        CRED --> PER_PID["per-pid: словарь credentials"]
        ENTER["neutralize_syscall()<br/>— подмена uid/gid аргументов"]
        EXIT["handle_syscall_exit()<br/>— get*id: подмена результата<br/>— set*id: обновление credentials<br/>— chown: подмена owner"]
    end

    subgraph "Хост"
        HOST_USER["Реальный пользователь<br/>(не-root)"]
    end

    ID_SYSCALL --> ENTER
    ID_SYSCALL --> EXIT
    PER_PID --> HOST_USER
```

---

## Виртуальная сеть

```mermaid
flowchart TB
    subgraph "Tracee"
        APP_S["Сервер"] -- "bind(10.42.0.2:8080)" --> VNET
        APP_C["Клиент"] -- "connect(10.42.0.3:8000)" --> VNET
    end

    subgraph "VirtualNetworkRuntime (virtual_network.py)"
        VNET["VirtualNetworkRuntime"]
        VNET --> SOCK["prepare_bind()"]
        VNET --> CONN["prepare_connect()"]
        VNET --> NL["prepare_sendmsg/recvmsg<br/>(rtnetlink spoofing)"]
        VNET --> SNAME["handle_socket_name_exit()<br/>(getsockname/getpeername)"]
        
        SOCK --> NSC_BIND["NetworkServiceClient<br/>bind_request()"]
        CONN --> NSC_CONN["NetworkServiceClient<br/>connect_request()"]
        NL --> BUILD["build_rtnetlink_datagrams()"]
    end

    subgraph "netservice"
        NS["VirtualNetworkService"]
        NS --> REG["VirtualNetworkRegistry"]
        NS --> TCP["TcpProxyManager"]
    end

    subgraph "Реальность"
        LO["127.0.0.1: случайный порт"]
        PROXY["127.0.0.1: одноразовый proxy"]
    end

    NSC_BIND --> NS
    NSC_CONN --> NS
    NS --> REG
    NS --> TCP
    TCP --> PROXY
    NSC_BIND --> LO
```

---

## netservice (детально)

```mermaid
graph TB
    subgraph "netservice/"
        S["server.py<br/>VirtualNetworkService"]
        R["registry.py<br/>VirtualNetworkRegistry"]
        T["tcp_proxy.py<br/>TcpProxyManager"]
        P["protocol.py<br/>JSON-line encode/decode"]
        CLI["cli.py<br/>CLI client"]
    end

    subgraph "Типы сообщений"
        LC["allocate_container<br/>register_container<br/>release_container<br/>unregister_container"]
        ROUTE["bind_request<br/>connect_request"]
        MGMT["publish_port<br/>unpublish_port<br/>define_network<br/>remove_network<br/>peer_networks<br/>unpeer_networks"]
        INFO["list_networks<br/>list_publishes<br/>list_peerings<br/>list_containers"]
    end

    subgraph "Структуры данных"
        IFACE["InterfaceRecord<br/>(name, network, ip, ...)"]
        PM["PortMapping<br/>(virtual→real)"]
        PR["PublishRule<br/>(host:port→container:port)"]
        NET["NetworkState<br/>(subnet, gateway, allocated IPs)"]
    end

    S --> R
    S --> T
    S --> P
    CLI --> P
    S --> MGMT
    S --> INFO
    R --> LC
    R --> ROUTE
    R --> IFACE
    R --> PM
    R --> NET
    S --> PR
```

---

## Исполнение команд (Exec)

```mermaid
sequenceDiagram
    participant K as kubelet
    participant P as pnfroot (RuntimeService)
    participant RS as RemoteCommandServer (streaming.py)
    participant PT as ptrace_syscalls
    participant CONT as Контейнер

    K->>P: Exec(request)
    P->>P: exec_process = ExecStreamRequest(cmd, tty, stdin/stdout/stderr)

    alt Есть streaming server
        P->>RS: build_exec_url(request)
        RS-->>P: token + URL (ws://host:port/exec/token)
        P-->>K: URL (Streaming: true)
        K->>RS: WebSocket / SPDY connect
        Note over RS,CONT: Дальше всё идёт через streaming напрямую
    else Нет streaming server
        P->>PT: execsync(request)
        PT-->>P: stdout/stderr + exit_code
        P-->>K: ExecSyncResponse
    end

    rect rgb(200, 220, 240)
        Note over RS,CONT: WebSocket / SPDY протокол
        RS->>RS: negotiate_websocket_protocol()
        RS->>RS: negotiate_spdy_protocol()
        RS->>RS: serve_exec(request, stream)
        RS->>RS: start_process() → ContainerizedProcess
        RS->>CONT: pipe stdin (0) → процесс
        CONT->>RS: pipe stdout (1) → стрим
        RS->>RS: receive_loop() ← resize (4), stdin (0)
    end
```

---

## Pull образа и rootfs

```mermaid
flowchart LR
    subgraph "Запрос"
        REQ["PullImage(reference)"]
    end

    subgraph "image_store.py"
        REG_PARSE["parse_image_reference_for_registry()"]
        REG_PARSE --> SCHEME{"схема?"}
        SCHEME -- "docker://" --> REG_CLIENT["RegistryClient<br/>get_manifest()<br/>get_blob()"]
        SCHEME -- "file://" --> LOCAL["локальная директория"]
        SCHEME -- "directory" --> DIR["прямая директория"]

        REG_CLIENT --> VALIDATE["manifest_is_index()"]
        VALIDATE --> SELECT["select_platform_manifest()"]
        SELECT --> BLOBS["download blobs (config + layers)"]
        BLOBS --> SHA["sha256 validation"]
        SHA --> META["write_image_metadata()"]
    end

    subgraph "Распаковка"
        UNPACK["unpack_image_to_rootfs()"]
        UNPACK --> EXTRACT["extract_tar_safe()<br/>— защита от path traversal<br/>— игнорирование device nodes"]
        EXTRACT --> ROOTFS["rootfs/ готова"]
    end

    REQ --> REG_PARSE
    BLOBS --> UNPACK
```

---

## Схема данных

```mermaid
classDiagram
    class RuntimeService {
        +sandboxes: dict[str, PodSandboxState]
        +containers: dict[str, ContainerState]
        +images: ImageService
        +netservice: NetworkServiceClient
        +stream_server: RemoteCommandServer
        +RunPodSandbox(request) -> response
        +CreateContainer(request) -> response
        +StartContainer(request) -> response
        +ExecSync(request) -> response
        +save_runtime_state()
        +load_runtime_state()
    }

    class ContainerizedProcess {
        +pid: int
        +stdin: Pipe
        +stdout: Pipe
        +stderr: Pipe
        +poll() -> int
        +wait(timeout) -> int
    }

    class VirtualNetworkRuntime {
        +client: NetworkServiceClient
        +sockets: SocketTable
        +config: ContainerNetworkConfig
        +rewrite_syscall_entry()
        +handle_syscall_exit()
    }

    class VirtualRoot {
        +root: str
        +binds: list[BindMount]
        +pids: dict[int, str]
        +host_path(virtual) -> host
        +rewrite_syscall_entry()
    }

    class VirtualIds {
        +pids: dict[int, VirtualCredentials]
        +credentials(pid) -> VirtualCredentials
        +handle_syscall_exit()
        +neutralize_syscall()
    }

    class RemoteCommandServer {
        +runtime: RuntimeService
        +tokens: dict[str, ExecStreamRequest]
        +build_exec_url(request) -> str
        +serve_exec(request, stream)
    }

    class ImageService {
        +store_dir: str
        +images: list[ImageInfo]
        +PullImage(request) -> response
        +ListImages(request) -> response
    }

    class VirtualNetworkService {
        +registry: VirtualNetworkRegistry
        +proxy_manager: TcpProxyManager
        +handle_message(message) -> dict
    }

    RuntimeService *-- ContainerizedProcess : запускает
    RuntimeService --> VirtualNetworkRuntime : опционально
    RuntimeService --> RemoteCommandServer
    RuntimeService --> ImageService
    VirtualNetworkRuntime --> VirtualNetworkService : unix socket
    VirtualNetworkRuntime --> SocketTable
    VirtualNetworkRuntime --> ContainerNetworkConfig
```

---

## Структура директорий

```mermaid
graph TD
    ROOT["pnfroot/"] --> PNF["pnfroot.py — CRI runtime server"]
    ROOT --> PTRACE["ptrace_syscalls.py — ptrace tracer"]
    ROOT --> PCOMMON["ptrace_common.py — ptrace primitives"]
    ROOT --> VNET["virtual_network.py — virtual network"]
    ROOT --> VPATHS["virtual_paths.py — virtual filesystem"]
    ROOT --> VIDS["virtual_ids.py — virtual uid/gid"]
    ROOT --> CRI["cri_common.py — shared CRI utils"]
    ROOT --> IMG["image_service.py — CRI ImageService"]
    ROOT --> ISTORE["image_store.py — OCI registry + unpack"]
    ROOT --> STREAM["streaming.py — Exec/Attach streaming"]
    ROOT --> README["README.md"]

    ROOT --> NS["netservice/"]
    NS --> NSS["server.py — VirtualNetworkService"]
    NS --> NSR["registry.py — VirtualNetworkRegistry"]
    NS --> NST["tcp_proxy.py — TcpProxyManager"]
    NS --> NSP["protocol.py — JSON-line encode/decode"]
    NS --> NSC["cli.py — CLI client"]

    ROOT --> TOOLS["tools/"]
    TOOLS --> PROTO["api.proto — CRI gRPC spec"]
    TOOLS --> PB2["api_pb2.py — generated proto types"]
    TOOLS --> PB2GRPC["api_pb2_grpc.py — generated gRPC stubs"]

    ROOT --> TESTS["tests/"]
    TESTS --> TP["test_pnfroot.py — unit/integration"]
    TESTS --> TV["test_virtual_network.py — network tests"]
    TESTS --> TN["test_netservice_integration.py — netservice tests"]
    TESTS --> FIXTURES["fixtures/ — test data"]

    ROOT --> DOCS["docs/"]
    DOCS --> ARCH["architecture.md — диаграммы"]
    DOCS --> NET["networking_ru.md — документация сети"]
