from __future__ import annotations

import argparse
import json
import sys
import time

from .backend import PktmonBackend
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
            backend.start(
                args.filter,
                queue_capacity=args.queue_size,
                buffer_size_multiplier=args.buffer_size_multiplier,
                truncation_size=args.truncation_size,
                include_empty_payloads=not args.payload_only,
            )
        except Exception as exc:
            print("failed to start capture: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
            return 2
        print("printing parsed packets; press Ctrl+C to stop", flush=True)
        try:
            while deadline is None or time.monotonic() < deadline:
                packets = backend.read_many(
                    max_packets=args.drain_batch_size,
                    timeout_ms=args.read_timeout_ms,
                )
                if not packets:
                    continue
                for packet in packets:
                    count += 1
                    print(_format_packet(count, packet, args.hex), flush=False)
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("stopping", flush=True)
    if count == 0:
        print("captured packets: 0", flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Python interface for Windows pktmon.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("probe", help="Print native backend probe information.").set_defaults(func=command_probe)

    packets = subparsers.add_parser("packets", help="Print live packets from the native backend.")
    packets.add_argument("--filter", default=DEFAULT_FILTER)
    packets.add_argument("--timeout", type=float, default=30.0)
    packets.add_argument("--hex", type=int, default=32)
    packets.add_argument("--queue-size", type=int, default=8192)
    packets.add_argument("--buffer-size-multiplier", type=int, default=1)
    packets.add_argument("--truncation-size", type=int, default=9000)
    packets.add_argument("--read-timeout-ms", type=int, default=50)
    packets.add_argument("--drain-batch-size", type=int, default=64)
    packets.add_argument("--payload-only", action="store_true")
    packets.add_argument("--probe", action="store_true")
    packets.set_defaults(func=command_packets)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
