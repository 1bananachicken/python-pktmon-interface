# pktmon-interface

Generic Python interface for Windows `pktmon` packet capture.

It provides:

- a small C++ shim DLL over `PktMonApi.dll` realtime streams;
- a Python `ctypes` wrapper exposed as `pktmon_interface.PktmonBackend`;
- a Scapy-shaped async sniffer exposed as `pktmon_interface.PktmonSniffer`;
- a single CLI, `pktmon-interface`.

The live capture path is Windows-only and generally requires an elevated
Administrator terminal.

## Layout

```text
native/include/              C ABI consumed by Python
native/src/                  Windows C++ pktmon shim
scripts/build.ps1            MSVC build helper
src/pktmon_interface/        Python package
```

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\activate
python -m pip install -e .[dev]
```

Build the native DLL:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1
```

The default output is:

```text
build/pktmon_backend.dll
```

You can point Python at another DLL with:

```powershell
$env:PKTMON_BACKEND_DLL = "C:\path\to\pktmon_backend.dll"
```

## Package build

Build a pip-installable wheel with the native DLL bundled:

```powershell
python -m pip install build
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1 -OutputDir .\src\pktmon_interface
python -m build
```

The wheel is written to `dist/` and is tagged as a Windows x64 platform wheel,
for example:

```text
pktmon_interface-0.1.0-py3-none-win_amd64.whl
```

GitHub Actions runs tests on Python 3.10 through 3.13, builds the native DLL,
builds the wheel/sdist, and uploads the distributions as workflow artifacts.
Pushing a tag like `v0.1.0` also attaches those distributions to the GitHub
release and publishes them to PyPI with the `PYPI_API_TOKEN` repository secret.

## Python API

Scapy-like callback use:

```python
from pktmon_interface import CapturedPacket, PktmonSniffer


def on_packet(packet: CapturedPacket) -> None:
    print(packet.protocol_name, packet.source, packet.destination, len(packet.payload))


sniffer = PktmonSniffer(filter="tcp port 30031 or udp", prn=on_packet, store=False)
sniffer.start()
try:
    sniffer.join(timeout=30)
finally:
    sniffer.stop()
```

Capture tuning:

```python
sniffer = PktmonSniffer(
    filter="udp",
    store=False,
    queue_size=8192,
    native_queue_capacity=8192,
    buffer_size_multiplier=1,
    truncation_size=9000,
    include_empty_payloads=True,
    drain_batch_size=64,
)
```

`include_empty_payloads=True` counts TCP/UDP packets with no payload, such as
TCP ACK and handshake packets. This usually makes packet event counts closer to
Scapy. Set it to `False` to keep the older payload-only behavior. For higher
event rates, keep callback work small, use `store=False`, and lower
`truncation_size` if you only need packet metadata instead of full payloads.
`buffer_size_multiplier=1` favors low latency; increase it if you see packet
drops under bursts.

Synchronous reads:

```python
from pktmon_interface import PktmonBackend

with PktmonBackend() as backend:
    print(backend.probe())
    backend.start(
        "tcp port 30031 or udp",
        queue_capacity=8192,
        buffer_size_multiplier=1,
        include_empty_payloads=True,
    )
    packet = backend.read(timeout_ms=500)
    if packet is not None:
        print(packet.protocol_name, packet.source, packet.destination, len(packet.payload))
```

Iterator style:

```python
from pktmon_interface import PktmonSniffer

with PktmonSniffer(filter="udp", store=False) as sniffer:
    for packet in sniffer:
        print(packet.flow, packet.payload[:16].hex(" "))
```

## CLI

```powershell
pktmon-interface probe
pktmon-interface packets --timeout 30 --probe
pktmon-interface packets --timeout 30 --queue-size 8192 --buffer-size-multiplier 1
```

The native backend defaults to the documented `PktMonApi.dll` realtime stream
and applies capture constraints to its own live session. If `PktMonApi.dll` is
missing or does not expose the required realtime stream exports, startup fails
with an error instead of falling back to another capture path.

## Notes

The native backend does not use `pktmon filter` global system state. It only
uses session capture constraints through `PktMonApi.dll`.

## Validation

Offline validation:

```powershell
python -m py_compile (Get-ChildItem -Recurse -Filter *.py src).FullName
powershell -ExecutionPolicy Bypass -File .\scripts\build.ps1
```
