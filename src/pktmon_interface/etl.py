from __future__ import annotations

import ipaddress
import shutil
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .models import PROTO_TCP, PROTO_UDP, CapturedPacket


@dataclass(frozen=True)
class CaptureChunk:
    packets: list[CapturedPacket]
    raw_packets: int
    parsed_packets: int
    linktypes: tuple[int, ...]
    block_types: tuple[int, ...]
    pcap_size: int
    etl_size: int
    sample_linktype: int
    sample_hex: str


def _run_pktmon(args: list[str], check: bool = True) -> str:
    result = subprocess.run(
        ["pktmon", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            "pktmon %s failed with code %s:\n%s"
            % (" ".join(args), result.returncode, result.stdout)
        )
    return result.stdout


def _filter_port(packet_filter: str, marker: str) -> int | None:
    lower = packet_filter.lower()
    index = lower.find(marker)
    if index < 0:
        return None
    value = lower[index + len(marker) :].strip().split(maxsplit=1)[0]
    return int(value) if value.isdigit() else None


def configure_filters(packet_filter: str) -> None:
    _run_pktmon(["filter", "remove"], check=False)
    lower = packet_filter.lower()
    commands: list[list[str]] = []
    if "tcp" in lower:
        command = ["filter", "add", "PktmonInterfaceEtlTcp", "-t", "TCP"]
        port = _filter_port(packet_filter, "tcp port")
        if port is None:
            port = _filter_port(packet_filter, "port")
        if port is not None:
            command += ["-p", str(port)]
        commands.append(command)
    if "udp" in lower:
        command = ["filter", "add", "PktmonInterfaceEtlUdp", "-t", "UDP"]
        port = _filter_port(packet_filter, "udp port")
        if port is not None:
            command += ["-p", str(port)]
        commands.append(command)
    if not commands:
        commands.append(["filter", "add", "PktmonInterfaceEtlAll"])
    for command in commands:
        _run_pktmon(command)


def _u16be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def _ipv4(data: bytes, offset: int) -> str:
    return ".".join(str(part) for part in data[offset : offset + 4])


def _ipv6(data: bytes, offset: int) -> str:
    return str(ipaddress.IPv6Address(data[offset : offset + 16]))


def _parse_ip_packet(data: bytes, offset: int, timestamp: float) -> CapturedPacket | None:
    if offset >= len(data):
        return None
    version = data[offset] >> 4
    if version == 4:
        if offset + 20 > len(data):
            return None
        ihl = (data[offset] & 0x0F) * 4
        if ihl < 20 or offset + ihl > len(data):
            return None
        total_length = _u16be(data, offset + 2)
        end = min(len(data), offset + total_length) if total_length >= ihl else len(data)
        proto = data[offset + 9]
        source = _ipv4(data, offset + 12)
        destination = _ipv4(data, offset + 16)
        transport = offset + ihl
    elif version == 6:
        if offset + 40 > len(data):
            return None
        payload_length = _u16be(data, offset + 4)
        end = min(len(data), offset + 40 + payload_length)
        proto = data[offset + 6]
        source = _ipv6(data, offset + 8)
        destination = _ipv6(data, offset + 24)
        transport = offset + 40
    else:
        return None

    if proto == PROTO_TCP:
        if transport + 20 > end:
            return None
        header = (data[transport + 12] >> 4) * 4
        if header < 20 or transport + header > end:
            return None
        sport = _u16be(data, transport)
        dport = _u16be(data, transport + 2)
        payload = data[transport + header : end]
    elif proto == PROTO_UDP:
        if transport + 8 > end:
            return None
        sport = _u16be(data, transport)
        dport = _u16be(data, transport + 2)
        payload = data[transport + 8 : end]
    else:
        return None

    if not payload:
        return None
    return CapturedPacket(timestamp, proto, source, sport, destination, dport, payload)


def _parse_ethernet(data: bytes, timestamp: float) -> CapturedPacket | None:
    if len(data) < 14:
        return None
    ethertype = _u16be(data, 12)
    offset = 14
    if ethertype == 0x8100 and len(data) >= 18:
        ethertype = _u16be(data, 16)
        offset = 18
    if ethertype not in {0x0800, 0x86DD}:
        return None
    return _parse_ip_packet(data, offset, timestamp)


def _parse_ieee80211(data: bytes, timestamp: float) -> CapturedPacket | None:
    if len(data) < 32:
        return None
    frame_control = data[0] | (data[1] << 8)
    frame_type = (frame_control >> 2) & 0x03
    subtype = (frame_control >> 4) & 0x0F
    if frame_type != 2:
        return None
    to_ds = bool(frame_control & 0x0100)
    from_ds = bool(frame_control & 0x0200)
    header = 24
    if to_ds and from_ds:
        header += 6
    if subtype & 0x08:
        header += 2
    if len(data) < header + 8:
        return None

    # Windows pktmon can export Wi-Fi frames as linktype 1 with a small pad
    # before LLC/SNAP. Search a tight window after the computed 802.11 header
    # instead of assuming the payload starts exactly at `header`.
    llc_offset = -1
    for candidate in range(header, min(header + 8, len(data) - 8) + 1):
        if data[candidate : candidate + 6] == b"\xaa\xaa\x03\x00\x00\x00":
            llc_offset = candidate
            break
    if llc_offset < 0:
        return None
    llc = data[llc_offset : llc_offset + 8]
    ethertype = _u16be(llc, 6)
    if ethertype not in {0x0800, 0x86DD}:
        return None
    return _parse_ip_packet(data, llc_offset + 8, timestamp)


def _parse_llc_snap_scan(data: bytes, timestamp: float) -> CapturedPacket | None:
    limit = min(64, max(0, len(data) - 8))
    for offset in range(0, limit + 1):
        if data[offset : offset + 6] != b"\xaa\xaa\x03\x00\x00\x00":
            continue
        ethertype = _u16be(data, offset + 6)
        if ethertype not in {0x0800, 0x86DD}:
            continue
        parsed = _parse_ip_packet(data, offset + 8, timestamp)
        if parsed is not None:
            return parsed
    return None


def _parse_radiotap(data: bytes, timestamp: float) -> CapturedPacket | None:
    if len(data) < 8:
        return None
    header_length = data[2] | (data[3] << 8)
    if header_length < 8 or header_length >= len(data):
        return None
    return _parse_ieee80211(data[header_length:], timestamp)


def parse_packet(linktype: int, data: bytes, timestamp: float) -> CapturedPacket | None:
    if linktype == 1:
        return _parse_ethernet(data, timestamp) or _parse_llc_snap_scan(data, timestamp)
    if linktype == 101:
        return _parse_ip_packet(data, 0, timestamp)
    if linktype == 105:
        return _parse_ieee80211(data, timestamp)
    if linktype == 127:
        return _parse_radiotap(data, timestamp)
    # PktMon can emit Wi-Fi packets under build-specific link types. Try the
    # common decoders before giving up.
    return (
        _parse_ethernet(data, timestamp)
        or _parse_ip_packet(data, 0, timestamp)
        or _parse_llc_snap_scan(data, timestamp)
        or _parse_radiotap(data, timestamp)
        or _parse_ieee80211(data, timestamp)
    )


def inspect_pcapng(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    offset = 0
    endian = "<"
    linktypes: list[int] = []
    block_types: list[int] = []
    packets: list[tuple[int, float, bytes]] = []
    while offset + 12 <= len(data):
        block_type, block_length = struct.unpack_from(endian + "II", data, offset)
        if block_length < 12 or offset + block_length > len(data):
            break
        block_types.append(block_type)
        body = offset + 8
        if block_type == 0x0A0D0D0A:
            byte_order = struct.unpack_from("<I", data, body)[0]
            endian = "<" if byte_order == 0x1A2B3C4D else ">"
        elif block_type == 0x00000001 and body + 8 <= len(data):
            linktype = struct.unpack_from(endian + "H", data, body)[0]
            linktypes.append(linktype)
        elif block_type == 0x00000006 and body + 20 <= len(data):
            interface_id, ts_high, ts_low, captured_len, _original_len = struct.unpack_from(
                endian + "IIIII", data, body
            )
            packet_offset = body + 20
            packet_end = packet_offset + captured_len
            if packet_end <= offset + block_length - 4:
                timestamp = time.time()
                if interface_id < len(linktypes):
                    packets.append((linktypes[interface_id], timestamp, data[packet_offset:packet_end]))
                else:
                    packets.append((0, timestamp, data[packet_offset:packet_end]))
        elif block_type == 0x00000003 and body + 4 <= len(data):
            original_len = struct.unpack_from(endian + "I", data, body)[0]
            packet_offset = body + 4
            captured_len = min(original_len, offset + block_length - 4 - packet_offset)
            if captured_len > 0:
                linktype = linktypes[0] if linktypes else 0
                packets.append((linktype, time.time(), data[packet_offset : packet_offset + captured_len]))
        offset += block_length
    return {
        "linktypes": tuple(linktypes),
        "block_types": tuple(block_types),
        "packets": packets,
        "size": len(data),
    }


def iter_pcapng_packets(path: Path) -> Iterator[tuple[int, float, bytes]]:
    yield from inspect_pcapng(path)["packets"]


class PktmonEtlCapture:
    def __init__(
        self,
        packet_filter: str = "tcp port 30031 or udp",
        chunk_seconds: float = 0.75,
        work_dir: str | Path | None = None,
    ) -> None:
        self.packet_filter = packet_filter
        self.chunk_seconds = max(float(chunk_seconds), 0.2)
        self._own_dir = work_dir is None
        self.work_dir = Path(work_dir) if work_dir is not None else Path(tempfile.mkdtemp(prefix="pktmon_interface_"))
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._started = False

    def start(self) -> None:
        configure_filters(self.packet_filter)
        self._started = True

    def close(self) -> None:
        _run_pktmon(["stop"], check=False)
        _run_pktmon(["filter", "remove"], check=False)
        if self._own_dir:
            shutil.rmtree(self.work_dir, ignore_errors=True)
        self._started = False

    def capture_once(self) -> list[CapturedPacket]:
        return self.capture_chunk().packets

    def capture_chunk(self) -> CaptureChunk:
        if not self._started:
            raise RuntimeError("capture is not started")
        stamp = str(time.monotonic_ns())
        etl = self.work_dir / ("capture_%s.etl" % stamp)
        pcap = self.work_dir / ("capture_%s.pcapng" % stamp)
        _run_pktmon(
            [
                "start",
                "--capture",
                "--comp",
                "nics",
                "--pkt-size",
                "0",
                "--flags",
                "0x10",
                "--file-name",
                str(etl),
            ]
        )
        time.sleep(self.chunk_seconds)
        _run_pktmon(["stop"], check=False)
        _run_pktmon(["etl2pcap", str(etl), "--out", str(pcap)])
        packets: list[CapturedPacket] = []
        raw_packets = 0
        linktypes: tuple[int, ...] = ()
        block_types: tuple[int, ...] = ()
        sample_linktype = 0
        sample_hex = ""
        pcap_size = pcap.stat().st_size if pcap.exists() else 0
        etl_size = etl.stat().st_size if etl.exists() else 0
        if pcap.exists():
            info = inspect_pcapng(pcap)
            linktypes = info["linktypes"]
            block_types = info["block_types"]
            raw_items = info["packets"]
            raw_packets = len(raw_items)
            if raw_items:
                sample_linktype = int(raw_items[0][0])
                sample_hex = raw_items[0][2][:96].hex(" ")
            for linktype, timestamp, packet in raw_items:
                parsed = parse_packet(linktype, packet, timestamp)
                if parsed is not None:
                    packets.append(parsed)
        etl.unlink(missing_ok=True)
        pcap.unlink(missing_ok=True)
        return CaptureChunk(
            packets=packets,
            raw_packets=raw_packets,
            parsed_packets=len(packets),
            linktypes=linktypes,
            block_types=block_types,
            pcap_size=pcap_size,
            etl_size=etl_size,
            sample_linktype=sample_linktype,
            sample_hex=sample_hex,
        )
