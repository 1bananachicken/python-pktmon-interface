from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pktmon_interface.etl import parse_packet  # noqa: E402
from pktmon_interface.models import PROTO_TCP, PROTO_UDP  # noqa: E402


def ipv4_header(protocol: int, source: bytes, destination: bytes, payload: bytes) -> bytes:
    total_length = 20 + len(payload)
    return (
        bytes([0x45, 0x00])
        + total_length.to_bytes(2, "big")
        + b"\x00\x00\x00\x00\x40"
        + bytes([protocol])
        + b"\x00\x00"
        + source
        + destination
        + payload
    )


class PacketParserTests(unittest.TestCase):
    def test_parse_ethernet_ipv4_tcp_payload(self) -> None:
        tcp = (
            (12345).to_bytes(2, "big")
            + (30031).to_bytes(2, "big")
            + b"\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x50\x18\x00\x00\x00\x00\x00\x00"
            + b"hello"
        )
        ip = ipv4_header(PROTO_TCP, b"\x0a\x00\x00\x02", b"\x08\x08\x08\x08", tcp)
        frame = b"\x00" * 12 + b"\x08\x00" + ip

        packet = parse_packet(1, frame, 123.0)

        self.assertIsNotNone(packet)
        assert packet is not None
        self.assertEqual(packet.protocol, PROTO_TCP)
        self.assertEqual(packet.source, "10.0.0.2")
        self.assertEqual(packet.destination, "8.8.8.8")
        self.assertEqual(packet.sport, 12345)
        self.assertEqual(packet.dport, 30031)
        self.assertEqual(packet.payload, b"hello")

    def test_parse_raw_ipv4_udp_payload(self) -> None:
        udp_payload = b"payload"
        udp = (
            (40000).to_bytes(2, "big")
            + (30031).to_bytes(2, "big")
            + (8 + len(udp_payload)).to_bytes(2, "big")
            + b"\x00\x00"
            + udp_payload
        )
        ip = ipv4_header(PROTO_UDP, b"\xc0\xa8\x01\x10", b"\x01\x01\x01\x01", udp)

        packet = parse_packet(101, ip, 456.0)

        self.assertIsNotNone(packet)
        assert packet is not None
        self.assertEqual(packet.protocol, PROTO_UDP)
        self.assertEqual(packet.source, "192.168.1.16")
        self.assertEqual(packet.destination, "1.1.1.1")
        self.assertEqual(packet.payload, udp_payload)


if __name__ == "__main__":
    unittest.main()
