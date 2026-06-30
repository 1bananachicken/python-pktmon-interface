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

Synchronous reads:

```python
from pktmon_interface import PktmonBackend

with PktmonBackend() as backend:
    print(backend.probe())
    backend.start("tcp port 30031 or udp")
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
