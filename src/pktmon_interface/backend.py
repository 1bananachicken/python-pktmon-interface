from __future__ import annotations

import ctypes
import os
import json
from pathlib import Path
from typing import Any

from .models import CapturedPacket


PKTMON_OK = 0
PKTMON_E_ABI_UNMAPPED = -6
PKTMON_E_NOT_STARTED = -5
PKTMON_E_TIMEOUT = -8


class ProbeInfo(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("export_count", ctypes.c_uint32),
        ("missing_count", ctypes.c_uint32),
        ("capture_ready", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32),
    ]


class NativePacket(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("timestamp_unix", ctypes.c_double),
        ("protocol", ctypes.c_uint32),
        ("source_port", ctypes.c_uint16),
        ("destination_port", ctypes.c_uint16),
        ("source_address", ctypes.c_char * 64),
        ("destination_address", ctypes.c_char * 64),
        ("payload", ctypes.POINTER(ctypes.c_uint8)),
        ("payload_size", ctypes.c_uint32),
    ]


class CaptureConfig(ctypes.Structure):
    _fields_ = [
        ("struct_size", ctypes.c_uint32),
        ("queue_capacity", ctypes.c_uint32),
        ("buffer_size_multiplier", ctypes.c_uint16),
        ("truncation_size", ctypes.c_uint16),
        ("include_empty_payloads", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 5),
    ]


class PktmonBackend:
    def __init__(self, dll_path: str | Path | None = None) -> None:
        if dll_path is None:
            dll_path = self.default_dll_path()
        self._dll_path = Path(dll_path)
        if not self._dll_path.exists():
            raise FileNotFoundError(
                "pktmon backend DLL was not found: %s. Run scripts/build.ps1 first "
                "or set PKTMON_BACKEND_DLL." % self._dll_path
            )
        self._dll = ctypes.CDLL(str(self._dll_path))
        self._bind()
        self._handle = self._dll.PktmonCreate()
        if not self._handle:
            raise RuntimeError("PktmonCreate failed")

    def _bind(self) -> None:
        dll = self._dll
        dll.PktmonVersion.argtypes = []
        dll.PktmonVersion.restype = ctypes.c_int32

        dll.PktmonProbe.argtypes = [ctypes.POINTER(ProbeInfo)]
        dll.PktmonProbe.restype = ctypes.c_int32

        dll.PktmonGetExportReport.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        dll.PktmonGetExportReport.restype = ctypes.c_uint32

        dll.PktmonCreate.argtypes = []
        dll.PktmonCreate.restype = ctypes.c_void_p

        dll.PktmonDestroy.argtypes = [ctypes.c_void_p]
        dll.PktmonDestroy.restype = None

        dll.PktmonStart.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        dll.PktmonStart.restype = ctypes.c_int32

        self._start_config = getattr(dll, "PktmonStartConfig", None)
        if self._start_config is not None:
            self._start_config.argtypes = [
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.POINTER(CaptureConfig),
            ]
            self._start_config.restype = ctypes.c_int32

        dll.PktmonRead.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(NativePacket),
            ctypes.c_uint32,
        ]
        dll.PktmonRead.restype = ctypes.c_int32

        self._read_batch = getattr(dll, "PktmonReadBatch", None)
        if self._read_batch is not None:
            self._read_batch.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(NativePacket),
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
            ]
            self._read_batch.restype = ctypes.c_int32

        dll.PktmonStop.argtypes = [ctypes.c_void_p]
        dll.PktmonStop.restype = None

        dll.PktmonLastError.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        dll.PktmonLastError.restype = ctypes.c_uint32

    @property
    def version(self) -> int:
        return int(self._dll.PktmonVersion())

    @staticmethod
    def default_dll_path() -> Path:
        env_path = os.environ.get("PKTMON_BACKEND_DLL")
        if env_path:
            return Path(env_path)

        module_dir = Path(__file__).resolve().parent
        project_root = module_dir.parents[1]
        candidates = [
            module_dir / "pktmon_backend.dll",
            project_root / "build" / "pktmon_backend.dll",
            project_root / "native" / "build" / "pktmon_backend.dll",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[1]

    def probe(self) -> dict[str, Any]:
        info = ProbeInfo()
        info.struct_size = ctypes.sizeof(ProbeInfo)
        status = int(self._dll.PktmonProbe(ctypes.byref(info)))
        report_size = int(self._dll.PktmonGetExportReport(None, 0))
        buffer = ctypes.create_string_buffer(report_size)
        self._dll.PktmonGetExportReport(buffer, report_size)
        report = json.loads(buffer.value.decode("utf-8"))
        return {
            "status": status,
            "version": self.version,
            "export_count": int(info.export_count),
            "missing_count": int(info.missing_count),
            "capture_ready": bool(info.capture_ready),
            "report": report,
        }

    def start(
        self,
        packet_filter: str = "tcp port 30031 or udp",
        *,
        queue_capacity: int = 8192,
        buffer_size_multiplier: int = 4,
        truncation_size: int = 9000,
        include_empty_payloads: bool = True,
    ) -> None:
        encoded_filter = packet_filter.encode("utf-8")
        if self._start_config is not None:
            config = CaptureConfig()
            config.struct_size = ctypes.sizeof(CaptureConfig)
            config.queue_capacity = max(int(queue_capacity), 1)
            config.buffer_size_multiplier = min(max(int(buffer_size_multiplier), 1), 65535)
            config.truncation_size = min(max(int(truncation_size), 1), 65535)
            config.include_empty_payloads = 1 if include_empty_payloads else 0
            status = int(
                self._start_config(
                    self._handle,
                    encoded_filter,
                    ctypes.byref(config),
                )
            )
        else:
            status = int(self._dll.PktmonStart(self._handle, encoded_filter))
        if status != PKTMON_OK:
            raise RuntimeError("PktmonStart failed: %s" % self.last_error())

    def read(self, timeout_ms: int = 100) -> CapturedPacket | None:
        packet = NativePacket()
        packet.struct_size = ctypes.sizeof(NativePacket)
        status = int(self._dll.PktmonRead(self._handle, ctypes.byref(packet), timeout_ms))
        if status in {PKTMON_E_NOT_STARTED, PKTMON_E_TIMEOUT}:
            return None
        if status != PKTMON_OK:
            raise RuntimeError("PktmonRead failed: %s" % self.last_error())
        return self._packet_from_native(packet)

    def read_many(self, max_packets: int = 64, timeout_ms: int = 100) -> list[CapturedPacket]:
        limit = max(int(max_packets), 1)
        if self._read_batch is not None:
            native_packets = (NativePacket * limit)()
            struct_size = ctypes.sizeof(NativePacket)
            for packet in native_packets:
                packet.struct_size = struct_size
            packets_read = ctypes.c_uint32(0)
            status = int(
                self._read_batch(
                    self._handle,
                    native_packets,
                    limit,
                    timeout_ms,
                    ctypes.byref(packets_read),
                )
            )
            if status in {PKTMON_E_NOT_STARTED, PKTMON_E_TIMEOUT}:
                return []
            if status != PKTMON_OK:
                raise RuntimeError("PktmonReadBatch failed: %s" % self.last_error())
            return [
                self._packet_from_native(native_packets[index])
                for index in range(int(packets_read.value))
            ]

        first = self.read(timeout_ms=timeout_ms)
        if first is None:
            return []

        packets = [first]
        while len(packets) < limit:
            packet = self.read(timeout_ms=0)
            if packet is None:
                break
            packets.append(packet)
        return packets

    @staticmethod
    def _packet_from_native(packet: NativePacket) -> CapturedPacket:
        payload = (
            b""
            if packet.payload_size == 0
            else ctypes.string_at(packet.payload, packet.payload_size)
        )
        return CapturedPacket(
            timestamp=float(packet.timestamp_unix),
            protocol=int(packet.protocol),
            source=packet.source_address.split(b"\0", 1)[0].decode("ascii"),
            sport=int(packet.source_port),
            destination=packet.destination_address.split(b"\0", 1)[0].decode("ascii"),
            dport=int(packet.destination_port),
            payload=payload,
        )

    def last_error(self) -> str:
        size = int(self._dll.PktmonLastError(self._handle, None, 0))
        buffer = ctypes.create_string_buffer(max(size, 1))
        self._dll.PktmonLastError(self._handle, buffer, len(buffer))
        return buffer.value.decode("utf-8", errors="replace")

    def close(self) -> None:
        handle = getattr(self, "_handle", None)
        if handle:
            self._dll.PktmonStop(handle)
            self._dll.PktmonDestroy(handle)
            self._handle = None

    def __enter__(self) -> "PktmonBackend":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

