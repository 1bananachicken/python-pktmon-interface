from __future__ import annotations

from dataclasses import dataclass


PROTO_TCP = 6
PROTO_UDP = 17


@dataclass(frozen=True)
class CapturedPacket:
    timestamp: float
    protocol: int
    source: str
    sport: int
    destination: str
    dport: int
    payload: bytes

    @property
    def protocol_name(self) -> str:
        if self.protocol == PROTO_TCP:
            return "TCP"
        if self.protocol == PROTO_UDP:
            return "UDP"
        return str(self.protocol)

    @property
    def flow(self) -> tuple[str, int, str, int, str]:
        return (
            self.source,
            self.sport,
            self.destination,
            self.dport,
            self.protocol_name if self.protocol in {PROTO_TCP, PROTO_UDP} else "",
        )
