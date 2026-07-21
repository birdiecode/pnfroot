# pnfroot.py

Файл pnfroot.py реализует простой CRI-like gRPC-сервер для:
- PullImage
- RunPodSandbox
- CreateContainer
- StartContainer
- ListContainers
- ContainerStatus

## Запуск

```bash
cd /home/birdiecode/Documents/tk8s/pnfroot
. .venv/bin/activate
python pnfroot.py --socket-path /tmp/pnfroot.sock --image-store-dir /tmp/pnfroot/images
```

## Пример работы

1. Pull image из локального каталога `ubuntu_c`:

```bash
python - <<'PY'
import grpc
import example.tools.api_pb2 as api_pb2
import example.tools.api_pb2_grpc as api_pb2_grpc

channel = grpc.insecure_channel('unix:///tmp/pnfroot.sock')
stub = api_pb2_grpc.ImageServiceStub(channel)
resp = stub.PullImage(api_pb2.PullImageRequest(image=api_pb2.ImageSpec(image='ubuntu_c')))
print(resp.image_ref)
PY
```

2. Создать sandbox и контейнер:

```bash
python - <<'PY'
import grpc
import example.tools.api_pb2 as api_pb2
import example.tools.api_pb2_grpc as api_pb2_grpc

channel = grpc.insecure_channel('unix:///tmp/pnfroot.sock')
runtime = api_pb2_grpc.RuntimeServiceStub(channel)

sandbox = runtime.RunPodSandbox(api_pb2.RunPodSandboxRequest(config=api_pb2.PodSandboxConfig(metadata=api_pb2.PodSandboxMetadata(name='demo'))))
container = runtime.CreateContainer(api_pb2.CreateContainerRequest(
    pod_sandbox_id=sandbox.pod_sandbox_id,
    config=api_pb2.ContainerConfig(
        metadata=api_pb2.ContainerMetadata(name='demo'),
        image=api_pb2.ImageSpec(image='ubuntu_c'),
        command=['/bin/sh'],
        args=['-c', 'echo hello from pnfroot'],
    ),
))
runtime.StartContainer(api_pb2.StartContainerRequest(container_id=container.container_id))
print(container.container_id)
PY
```
