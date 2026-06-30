from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from .backend import PktmonBackend
from .etl import PktmonEtlCapture
from .models import CapturedPacket


DEFAULT_FILTER = "tcp port 30031 or udp"


def _format_packet(index: int, packet: CapturedPacket, hex_bytes: int = 32) -> str:
    line = (
        "#%d %s %s:%d -> %s:%d payload=%d"
        % (
            index,
            packet.protocol_name,
            packet.source,
            packet.sport,
            packet.destination,
            packet.dport,
            len(packet.payload),
        )
    )
    if hex_bytes > 0:
        line += " hex=" + packet.payload[:hex_bytes].hex(" ")
    return line


def _run_pktmon(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        ["pktmon", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.returncode, proc.stdout


def _configure_raw_filter(packet_filter: str) -> None:
    _run_pktmon(["filter", "remove"])
    lower = packet_filter.lower()
    commands: list[list[str]] = []
    if "tcp" in lower:
        port = "30031"
        marker = "tcp port"
        index = lower.find(marker)
        if index >= 0:
            value = lower[index + len(marker) :].strip().split(maxsplit=1)[0]
            if value.isdigit():
                port = value
        commands.append(["filter", "add", "PktmonInterfaceRawTcp", "-t", "TCP", "-p", port])
    if "udp" in lower:
        commands.append(["filter", "add", "PktmonInterfaceRawUdp", "-t", "UDP"])
    if not commands:
        commands.append(["filter", "add", "PktmonInterfaceRawAll"])

    for command in commands:
        code, output = _run_pktmon(command)
        print("> pktmon %s" % " ".join(command), flush=True)
        if output.strip():
            print(output.rstrip(), flush=True)
        if code != 0:
            raise RuntimeError("pktmon filter command failed with code %s" % code)


def command_probe(_args: argparse.Namespace) -> int:
    with PktmonBackend() as backend:
        print(json.dumps(backend.probe(), ensure_ascii=False, indent=2))
        try:
            backend.start(DEFAULT_FILTER)
        except RuntimeError as exc:
            print("start_check: %s" % exc)
        else:
            print("start_check: ok")
    return 0


def command_packets(args: argparse.Namespace) -> int:
    deadline = time.monotonic() + args.timeout if args.timeout > 0 else None
    count = 0
    with PktmonBackend() as backend:
        if args.probe:
            print(json.dumps(backend.probe(), ensure_ascii=False, indent=2), flush=True)
        print("starting pktmon packet capture; run as Administrator", flush=True)
        try:
            backend.start(args.filter)
        except Exception as exc:
            print("failed to start capture: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
            return 2
        print("printing parsed packets; press Ctrl+C to stop", flush=True)
        try:
            while deadline is None or time.monotonic() < deadline:
                packet = backend.read(timeout_ms=500)
                if packet is None:
                    continue
                count += 1
                print(_format_packet(count, packet, args.hex), flush=True)
        except KeyboardInterrupt:
            print("stopping", flush=True)
    if count == 0:
        print("captured packets: 0", flush=True)
    return 0


def command_etl_packets(args: argparse.Namespace) -> int:
    capture = PktmonEtlCapture(args.filter, chunk_seconds=args.chunk)
    deadline = time.monotonic() + args.timeout if args.timeout > 0 else None
    count = 0
    print("starting pktmon ETL packet capture; run as Administrator", flush=True)
    try:
        capture.start()
    except Exception as exc:
        print("failed to start capture: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2
    try:
        while deadline is None or time.monotonic() < deadline:
            chunk = capture.capture_chunk()
            if args.debug:
                print(
                    "chunk: etl=%d pcap=%d blocks=%s linktypes=%s raw=%d parsed=%d sample_linktype=%d"
                    % (
                        chunk.etl_size,
                        chunk.pcap_size,
                        sorted(set(chunk.block_types)),
                        list(chunk.linktypes),
                        chunk.raw_packets,
                        chunk.parsed_packets,
                        chunk.sample_linktype,
                    ),
                    flush=True,
                )
                if chunk.sample_hex:
                    print("sample_hex: %s" % chunk.sample_hex, flush=True)
            for packet in chunk.packets:
                count += 1
                print(_format_packet(count, packet, args.hex), flush=True)
    except KeyboardInterrupt:
        print("stopping", flush=True)
    finally:
        capture.close()
    return 0


def command_dump_raw(args: argparse.Namespace) -> int:
    output_path = Path(args.out)
    _configure_raw_filter(args.filter)
    command = [
        "pktmon",
        "start",
        "--capture",
        "--comp",
        "nics",
        "--pkt-size",
        args.pkt_size,
        "--flags",
        "0x10",
        "--log-mode",
        "real-time",
    ]
    print("> %s" % " ".join(command), flush=True)
    print("writing raw output to %s" % output_path, flush=True)

    with output_path.open("w", encoding="utf-8", errors="replace") as file:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

        def reader() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                file.write(line)
                file.flush()
                print(line, end="", flush=True)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        try:
            time.sleep(max(args.timeout, 0.1))
        finally:
            print("\n> pktmon stop", flush=True)
            _run_pktmon(["stop"])
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            thread.join(timeout=2)
            _run_pktmon(["filter", "remove"])
    print("saved raw output to %s" % output_path, flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Python interface for Windows pktmon.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("probe", help="Print native backend probe information.").set_defaults(func=command_probe)

    packets = subparsers.add_parser("packets", help="Print live packets from the native backend.")
    packets.add_argument("--filter", default=DEFAULT_FILTER)
    packets.add_argument("--timeout", type=float, default=30.0)
    packets.add_argument("--hex", type=int, default=32)
    packets.add_argument("--probe", action="store_true")
    packets.set_defaults(func=command_packets)

    etl_packets = subparsers.add_parser("etl-packets", help="Print packets from ETL chunks.")
    etl_packets.add_argument("--filter", default=DEFAULT_FILTER)
    etl_packets.add_argument("--chunk", type=float, default=0.75)
    etl_packets.add_argument("--timeout", type=float, default=10.0)
    etl_packets.add_argument("--hex", type=int, default=24)
    etl_packets.add_argument("--debug", action="store_true")
    etl_packets.set_defaults(func=command_etl_packets)

    dump_raw = subparsers.add_parser("dump-raw", help="Dump raw pktmon real-time stdout.")
    dump_raw.add_argument("--filter", default=DEFAULT_FILTER)
    dump_raw.add_argument("--timeout", type=float, default=20.0)
    dump_raw.add_argument("--pkt-size", default="0")
    dump_raw.add_argument("--out", default="raw_pktmon_output.txt")
    dump_raw.set_defaults(func=command_dump_raw)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
