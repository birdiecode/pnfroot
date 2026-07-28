# Прототип виртуальной сети

Проект не создаёт сетевые пространства имён Linux или хостовые интерфейсы.
Контейнерная сеть существует в ptrace-рантайме и во внешнем Unix-socket сервисе.

## Параметры запуска

Запуск сервиса:

```bash
python3 -m netservice.server --socket /tmp/net.unix
```

Флаг `--log` или `--verbose` включает логирование регистрации, bind, connect
и решений маршрутизации.

Разрешить выбранным логическим сетям доступ к невиртуальным IP через хостовую сеть:

```bash
python3 -m netservice.server \
  --socket /tmp/net.unix \
  --internet-networks backend,frontend
```

`--internet-networks` можно указывать несколько раз. Адреса внутри виртуальной
подсети, не зарегистрированные в реестре, по-прежнему блокируются, а не
пропускаются как внешние.

Запуск контейнера с одним виртуальным интерфейсом:

```bash
./ptrace_syscalls.py \
  --container-id app-01 \
  --rootfs ./app_rootfs \
  --netdev 'name=eth0,network=backend,ip=10.20.0.10/24,gateway=10.20.0.1' \
  --netservice /tmp/net.unix \
  -- ./app
```

Проброс TCP-порта из контейнера на хост:

```bash
./ptrace_syscalls.py \
  --container-id web-01 \
  --rootfs ./ubuntu_c \
  --netdev 'name=eth0,network=testnet' \
  --netservice /tmp/net.unix \
  --publish 18080:8000 \
  -- python3 -m http.server 8000 --bind 0.0.0.0
```

Подключение с хоста:

```bash
curl http://127.0.0.1:18080/
```

`--publish` можно повторять; принимает форматы:

```text
HOST_PORT:CONTAINER_PORT
HOST_IP:HOST_PORT:CONTAINER_PORT
HOST_PORT:CONTAINER_PORT/tcp
```

Хостовый IP по умолчанию — `127.0.0.1`. UDP пока не реализован.

Рантайм по умолчанию работает без логов. Флаг `--log` или `--verbose` включает
трассировку системных вызовов. Используйте `--log` на стороне сервиса для
отображения решений о маршрутизации, bind, proxy и блокировках. Старый флаг
`--quiet` принимается для совместимости, но тихий режим и так включён по
умолчанию.

Запуск второго контейнера в той же логической сети:

```bash
./ptrace_syscalls.py \
  --container-id db-01 \
  --rootfs ./db_rootfs \
  --netdev 'name=eth0,network=backend,ip=10.20.0.20/24,gateway=10.20.0.1' \
  --netservice /tmp/net.unix \
  -- ./database
```

Если `ip` не указан, сервис назначает IPv4-адрес из детерминированной подсети
`/24` для данной сети:

```bash
./ptrace_syscalls.py \
  --container-id test-client \
  --rootfs ./ubuntu_c \
  --netdev 'name=eth0,network=testnet' \
  --netservice /tmp/net.unix \
  -- curl http://10.50.0.20:8080
```

`--netdev` принимает поля:

```text
name      обязательно, имя интерфейса, видимое в виртуальном рантайме
network   обязательно, имя логической сети
ip        опционально, адрес с необязательным префиксом, например 10.20.0.15/24
gateway   опциональный виртуальный шлюз
mac       опциональный виртуальный MAC-адрес
mtu       опционально, MTU, по умолчанию 1500
dns       опционально, DNS-сервер; можно повторить поле или разделить значения точкой с запятой
```

`--netdev` требует `--netservice`. `--container-id` опционален; если не указан,
рантайм генерирует ID вида `container-8f42c7`.

Можно указывать несколько `--netdev`. Прототип маршрутизирует IPv4 TCP через
первый интерфейс, чей префикс содержит адрес назначения, иначе через первый
настроенный интерфейс.

## Протокол

Рантайм подключается к `--netservice` через Unix stream-сокет. Сообщения — это
JSON-объекты, разделённые символом новой строки, с полем `version: 1`.

Регистрация:

```json
{"version":1,"type":"register_container","container_id":"app-01","pid":15432,"interfaces":[{"name":"eth0","network":"backend","ip":"10.20.0.10","prefix_length":24,"gateway":"10.20.0.1","mac":null,"mtu":1500,"dns":[]}]}
```

Запрос на подключение:

```json
{"version":1,"type":"connect_request","request_id":"req-7ab18f","container_id":"app-01","pid":15432,"tid":15435,"fd":7,"protocol":"tcp","address_family":"ipv4","source":{"interface":"eth0","network":"backend","ip":"10.20.0.10","port":0},"destination":{"ip":"10.20.0.20","port":5432}}
```

Сервис возвращает `allow`, `deny`, `redirect` или `proxy`. Для
зарегистрированных виртуальных портов возвращается `proxy`:

```json
{"version":1,"type":"connect_result","request_id":"req-7ab18f","action":"proxy","connection_id":"conn-f14c23","proxy":{"ip":"127.0.0.1","port":18080}}
```

Запрос на привязку порта (bind):

```json
{"version":1,"type":"bind_request","request_id":"req-b18c21","container_id":"db-01","pid":15432,"fd":5,"protocol":"tcp","interface":"eth0","network":"backend","virtual_address":{"ip":"10.20.0.20","port":5432}}
```

Сервис возвращает loopback-адрес. Рантайм переписывает `sockaddr_in` до того,
как ядро увидит `bind(2)`:

```json
{"version":1,"type":"bind_result","request_id":"req-b18c21","action":"redirect","real_address":{"ip":"127.0.0.1","port":31245}}
```

Отмена регистрации:

```json
{"version":1,"type":"unregister_container","container_id":"app-01"}
```

## API управления

Тот же Unix-сокет принимает управляющие команды для динамической
перенастройки сервиса без перезапуска.

### Проброс портов

Добавление правила проброса порта для запущенного контейнера:

```json
{"version":1,"type":"publish_port","container_id":"web-01","host_ip":"0.0.0.0","host_port":8080,"container_port":80,"protocol":"tcp"}
```

- `host_ip` — корректный IPv4-адрес (используйте `"0.0.0.0"` для всех интерфейсов).
- `host_port` и `container_port` — от 1 до 65535.
- Поддерживается только `tcp`.

Если контейнер уже вызвал `bind` для этого порта, хостовый слушатель
запускается немедленно. Иначе правило сохраняется и активируется при
последующем bind контейнера.

Удаление одного правила:

```json
{"version":1,"type":"unpublish_port","container_id":"web-01","host_ip":"0.0.0.0","host_port":8080}
```

Удаление всех правил контейнера:

```json
{"version":1,"type":"unpublish_port","container_id":"web-01","all":true}
```

### Жизненный цикл сетей

Создание новой виртуальной сети во время работы:

```json
{"version":1,"type":"define_network","name":"srvnet","subnet":"10.43.0.0/24","gateway":"10.43.0.1"}
```

`gateway` опционален; по умолчанию — первый адрес хоста в подсети.

Удаление сети и всех её портов:

```json
{"version":1,"type":"remove_network","name":"srvnet"}
```

### Связывание сетей (peering)

По умолчанию контейнеры могут достигать только IP внутри своей логической сети.
Peering разрешает маршрутизацию из исходной сети в целевую:

```json
{"version":1,"type":"peer_networks","source":"frontend","target":"backend"}
```

Отмена peering:

```json
{"version":1,"type":"unpeer_networks","source":"frontend","target":"backend"}
```

Peering направленный: `peer_networks A B` разрешает трафик от A к B, но не
от B к A (для двустороннего доступа укажите peering в обратную сторону).

### Контейнеры

Список зарегистрированных контейнеров, опционально с фильтром по сети:

```json
{"version":1,"type":"list_containers","network":"backend"}
```

`network` опционален — без него возвращаются все контейнеры.

Ответ:

```json
{"version":1,"type":"list_containers_result","success":true,"containers":[{"container_id":"app-01","pids":[15432],"leased":false,"interfaces":[{"name":"eth0","network":"backend","ip":"10.20.0.10","prefix_length":24,"gateway":"10.20.0.1","mac":null,"mtu":1500,"dns":[]}]}]}
```

### Интроспекция

Список всех определённых сетей с подсетями и количеством занятых адресов:

```json
{"version":1,"type":"list_networks"}
```

Ответ:

```json
{"version":1,"type":"list_networks_result","success":true,"networks":[{"name":"podnet","subnet":"10.88.0.0/24","gateway":"10.88.0.1","allocated":2},{"name":"srvnet","subnet":"10.43.0.0/24","gateway":"10.43.0.1","allocated":0}]}
```

Список всех активных форвардеров портов:

```json
{"version":1,"type":"list_publishes"}
```

### Связи (peering)

Список активных направленных связей между сетями:

```json
{"version":1,"type":"list_peerings"}
```

Ответ:

```json
{"version":1,"type":"list_peerings_result","success":true,"peerings":[{"source":"frontend","target":"backend"}]}
```

### Использование с `nc` (netcat)

Все управляющие команды используют тот же JSON-line протокол и могут
отправляться напрямую через `socat` или `nc`:

```bash
echo '{"version":1,"type":"define_network","name":"srvnet","subnet":"10.43.0.0/24"}' | nc -U /tmp/net.unix
```

## CLI

В составе пакета `netservice` есть CLI-интерфейс для всех управляющих команд:

```bash
python3 -m netservice.cli [путь_к_сокету] <команда>
```

Путь к сокету — опциональный позиционный аргумент (по умолчанию `/tmp/net.unix`).

### Управление сетями

```bash
# Создать сеть
python3 -m netservice.cli network define srvnet --subnet 10.43.0.0/24 --gateway 10.43.0.1

# Удалить сеть
python3 -m netservice.cli network remove srvnet

# Список сетей
python3 -m netservice.cli network list
```

### Проброс портов

```bash
# Добавить правило проброса
python3 -m netservice.cli publish add web-01 --host-port 8080 --container-port 80

# С указанием host IP
python3 -m netservice.cli publish add web-01 --host-ip 0.0.0.0 --host-port 443 --container-port 443

# Удалить правило
python3 -m netservice.cli publish remove web-01 --host-port 8080

# Удалить все правила контейнера
python3 -m netservice.cli publish remove web-01 --all

# Список активных пробросов
python3 -m netservice.cli publish list
```

### Контейнеры

```bash
# Все контейнеры
python3 -m netservice.cli container list

# Только в определённой сети
python3 -m netservice.cli container list --network backend
```

### Связывание сетей (peering)

```bash
# Разрешить трафик из frontend в backend
python3 -m netservice.cli peer add frontend backend
python3 -m netservice.cli peer add frontend backend

# Запретить
python3 -m netservice.cli peer remove frontend backend

# Список связей
python3 -m netservice.cli peer list
```

## Текущее поведение

Рантайм отслеживает `socket`, `connect`, `bind`, `accept`, `accept4`, `close`,
`dup`, `dup2`, `dup3`, `close_range`, `getsockname`, `getpeername`, `sendto`,
`sendmsg`, `write`, `recvmsg` и `ioctl(SIOCGIFTXQLEN)`.

Для сокетов `NETLINK_ROUTE` рантайм эмулирует минимальный rtnetlink dump,
используемый `ip a`: `RTM_GETLINK` и `RTM_GETADDR` возвращают `lo` плюс
настроенные виртуальные интерфейсы. Хостовые интерфейсы в dump не включаются.

Первый работающий сценарий — IPv4 TCP:

1. Серверный процесс вызывает `bind(10.20.0.20:8080)`.
2. Рантайм запрашивает у сервиса реальный loopback-адрес для bind.
3. Сервис сохраняет `backend / 10.20.0.20:8080 -> 127.0.0.1:PORT`.
4. Клиентский процесс вызывает `connect(10.20.0.20:8080)`.
5. Рантайм запрашивает у сервиса маршрут.
6. Сервис создаёт одноразовый TCP-прокси и возвращает его loopback-адрес.
7. Рантайм переписывает `sockaddr_in` клиента на адрес прокси.

## Ограничения

Прототип намеренно минимален:

* Реализован IPv4 TCP; IPv6 маршрутизация возвращает `EAFNOSUPPORT`.
* UDP не реализован.
* Выход в интернет включается отдельно для каждой логической сети через флаг
  `--internet-networks` на стороне сервиса. Без него подключение вида
  `curl 8.8.8.8` блокируется, если только этот адрес не представлен
  зарегистрированным виртуальным портом и маршрутом.
* Проброс портов на хост реализован для IPv4 TCP через `--publish` на стороне
  рантайма. Сервис запускает хостовый слушатель, когда контейнер вызывает `bind`
  для соответствующего виртуального порта.
* Виртуальный DNS-прокси пока отсутствует.
* Реализовано минимальное rtnetlink-обнаружение интерфейсов для `ip a`. Более
  широкие netlink-семейства/сообщения, другие `ioctl(SIOCGIF*)`, `/proc/net/*`
  и `/sys/class/net` пока эмулированы не полностью.
* Трафик между разными сетями по умолчанию запрещён. Используйте управляющую
  команду `peer_networks` для включения маршрутизации между логическими сетями.
* Регистрация `bind` оптимистична: если трассируемый процесс впоследствии не
  сможет выполнить bind в ядре, сервис сохраняет mapping до отмены регистрации
  контейнера.
* TCP-прокси создаётся одноразово на каждый `connect_request`.
