from __future__ import annotations

from pathlib import Path

from pktmon_interface import __version__
from pktmon_interface.backend import PktmonBackend
from pktmon_interface.cli import build_parser
from pktmon_interface.models import CapturedPacket


def test_version_is_exported() -> None:
    assert __version__ == "0.2.0"


def test_default_dll_path_honors_environment(monkeypatch) -> None:
    expected = Path("C:/custom/pktmon_backend.dll")
    monkeypatch.setenv("PKTMON_BACKEND_DLL", str(expected))

    assert PktmonBackend.default_dll_path() == expected


def test_captured_packet_protocol_and_flow() -> None:
    packet = CapturedPacket(
        timestamp=1.0,
        protocol=6,
        source="127.0.0.1",
        sport=1234,
        destination="127.0.0.1",
        dport=80,
        payload=b"hello",
    )

    assert packet.protocol_name == "TCP"
    assert packet.flow == ("127.0.0.1", 1234, "127.0.0.1", 80, "TCP")


def test_cli_parser_accepts_packets_command() -> None:
    args = build_parser().parse_args(
        [
            "packets",
            "--timeout",
            "1",
            "--hex",
            "8",
            "--queue-size",
            "4096",
            "--buffer-size-multiplier",
            "8",
            "--truncation-size",
            "256",
            "--read-timeout-ms",
            "25",
            "--drain-batch-size",
            "32",
            "--payload-only",
        ]
    )

    assert args.command == "packets"
    assert args.timeout == 1
    assert args.hex == 8
    assert args.queue_size == 4096
    assert args.buffer_size_multiplier == 8
    assert args.truncation_size == 256
    assert args.read_timeout_ms == 25
    assert args.drain_batch_size == 32
    assert args.payload_only is True
