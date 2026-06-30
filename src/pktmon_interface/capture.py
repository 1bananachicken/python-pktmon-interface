from __future__ import annotations

import queue
import threading
from collections.abc import Callable, Iterator
from typing import Any

from .backend import PktmonBackend
from .models import CapturedPacket


PacketCallback = Callable[[CapturedPacket], Any]


class PktmonSniffer:
    """Async pktmon packet sniffer with a Scapy-like shape."""

    def __init__(
        self,
        filter: str = "tcp port 30031 or udp",
        prn: PacketCallback | None = None,
        store: bool = True,
        backend: PktmonBackend | None = None,
        read_timeout_ms: int = 100,
        queue_size: int = 8192,
        native_queue_capacity: int = 8192,
        buffer_size_multiplier: int = 1,
        truncation_size: int = 9000,
        include_empty_payloads: bool = True,
        drain_batch_size: int = 64,
    ) -> None:
        self.filter = filter
        self.prn = prn
        self.store = store
        self.read_timeout_ms = max(int(read_timeout_ms), 1)
        self.native_queue_capacity = max(int(native_queue_capacity), 1)
        self.buffer_size_multiplier = max(int(buffer_size_multiplier), 1)
        self.truncation_size = max(int(truncation_size), 1)
        self.include_empty_payloads = bool(include_empty_payloads)
        self.drain_batch_size = max(int(drain_batch_size), 1)
        self._backend = backend
        self._owns_backend = backend is None
        self._packets: list[CapturedPacket] = []
        self._queue: queue.Queue[CapturedPacket] = queue.Queue(maxsize=max(queue_size, 1))
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self._started = False
        self._error: BaseException | None = None

    @property
    def results(self) -> list[CapturedPacket]:
        return list(self._packets)

    @property
    def running(self) -> bool:
        return self._started and self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self._started:
            return
        backend = self._backend or PktmonBackend()
        backend.start(
            self.filter,
            queue_capacity=self.native_queue_capacity,
            buffer_size_multiplier=self.buffer_size_multiplier,
            truncation_size=self.truncation_size,
            include_empty_payloads=self.include_empty_payloads,
        )
        self._backend = backend
        self._error = None
        self._stopping.clear()
        self._started = True
        self._thread = threading.Thread(target=self._run, name="PktmonSniffer", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        assert self._backend is not None
        try:
            while not self._stopping.is_set():
                packets = self._backend.read_many(
                    max_packets=self.drain_batch_size,
                    timeout_ms=self.read_timeout_ms,
                )
                if not packets:
                    continue
                for packet in packets:
                    if self.store:
                        self._packets.append(packet)
                    if self.prn is not None:
                        self.prn(packet)
                    try:
                        self._queue.put_nowait(packet)
                    except queue.Full:
                        pass
        except BaseException as exc:
            self._error = exc

    def read(self, timeout: float | None = None) -> CapturedPacket | None:
        if self._error is not None:
            raise RuntimeError("pktmon sniffer failed") from self._error
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def sniff(self, timeout: float | None = None, count: int = 0) -> list[CapturedPacket]:
        self.start()
        collected: list[CapturedPacket] = []
        deadline = None
        if timeout is not None:
            import time

            deadline = time.monotonic() + max(timeout, 0.0)
        while count <= 0 or len(collected) < count:
            wait = None
            if deadline is not None:
                import time

                wait = deadline - time.monotonic()
                if wait <= 0:
                    break
            packet = self.read(timeout=wait)
            if packet is None:
                if deadline is None:
                    continue
                break
            collected.append(packet)
        return collected

    def stop(self, join: bool = True, timeout: float = 2.0) -> None:
        self._stopping.set()
        if join:
            self.join(timeout=timeout)
        backend = self._backend
        if self._owns_backend:
            self._backend = None
        self._started = False
        if backend is not None and self._owns_backend:
            backend.close()

    def join(self, timeout: float | None = None) -> list[CapturedPacket]:
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        if self._error is not None:
            raise RuntimeError("pktmon sniffer failed") from self._error
        return self.results

    def __iter__(self) -> Iterator[CapturedPacket]:
        self.start()
        while self.running:
            packet = self.read(timeout=0.5)
            if packet is not None:
                yield packet

    def __enter__(self) -> "PktmonSniffer":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


class PktmonCapture(PktmonSniffer):
    """Backward-friendly alias for code that prefers capture terminology."""
