from __future__ import annotations

import socket

from .errors import RehostError


def packet(payload: str) -> bytes:
    encoded = payload.encode("ascii")
    checksum = sum(encoded) & 0xFF
    return b"$" + encoded + f"#{checksum:02x}".encode("ascii")


class RspClient:
    """Small GDB Remote Serial Protocol client for bounded QEMU service hooks."""

    def __init__(self, connection: socket.socket):
        self.connection = connection
        self.no_ack = False
        self._pending: bytes | None = None

    def command(self, payload: str) -> str:
        self.connection.sendall(packet(payload))
        reply = self._receive_packet()
        return reply.decode("ascii", errors="replace")

    def start_no_ack(self) -> None:
        if self.command("QStartNoAckMode") != "OK":
            raise RehostError("RSP_NO_ACK", "QEMU GDB stub rejected no-ack mode")
        self.no_ack = True

    def continue_guest(self) -> None:
        self.connection.sendall(packet("c"))

    def wait_stop(self) -> str:
        return self._receive_packet().decode("ascii", errors="replace")

    def read_u64_register(self, number: int) -> int:
        reply = self.command(f"p{number:x}")
        try:
            raw = bytes.fromhex(reply)
        except ValueError as exc:
            raise RehostError("RSP_REGISTER", "register response is not hexadecimal", {"register": number}) from exc
        if len(raw) != 8:
            raise RehostError(
                "RSP_REGISTER",
                "unexpected AArch64 register width",
                {"register": number, "bytes": len(raw)},
            )
        return int.from_bytes(raw, "little")

    def read_register_file(self) -> bytearray:
        reply = self.command("g")
        try:
            raw = bytearray.fromhex(reply)
        except ValueError as exc:
            raise RehostError("RSP_REGISTER", "register-file response is not hexadecimal") from exc
        if len(raw) < 33 * 8:
            raise RehostError("RSP_REGISTER", "AArch64 register file is shorter than the core register set")
        return raw

    @staticmethod
    def core_u64(register_file: bytearray, number: int) -> int:
        if not 0 <= number <= 32:
            raise RehostError("RSP_REGISTER", "core register number is out of range", {"register": number})
        offset = number * 8
        return int.from_bytes(register_file[offset : offset + 8], "little")

    @staticmethod
    def set_core_u64(register_file: bytearray, number: int, value: int) -> None:
        if not 0 <= number <= 32:
            raise RehostError("RSP_REGISTER", "core register number is out of range", {"register": number})
        offset = number * 8
        register_file[offset : offset + 8] = value.to_bytes(8, "little")

    def write_register_file(self, register_file: bytearray) -> None:
        if self.command(f"G{register_file.hex()}") != "OK":
            raise RehostError("RSP_REGISTER", "QEMU rejected a register-file write")

    def write_u64_register(self, number: int, value: int) -> None:
        encoded = value.to_bytes(8, "little").hex()
        if self.command(f"P{number:x}={encoded}") != "OK":
            raise RehostError("RSP_REGISTER", "QEMU rejected a register write", {"register": number})

    def write_memory(self, address: int, data: bytes) -> None:
        for offset in range(0, len(data), 256):
            chunk = data[offset : offset + 256]
            reply = self.command(f"M{address + offset:x},{len(chunk):x}:{chunk.hex()}")
            if reply != "OK":
                raise RehostError(
                    "RSP_MEMORY",
                    "QEMU rejected a guest memory write",
                    {"address": f"0x{address + offset:x}", "size": len(chunk)},
                )

    def _receive_packet(self) -> bytes:
        payload = bytearray()
        while True:
            marker = self.connection.recv(1)
            if not marker:
                raise RehostError("RSP_EOF", "QEMU GDB connection closed")
            if marker == b"$":
                break
            if marker == b"-":
                raise RehostError("RSP_NACK", "QEMU rejected an RSP packet")

        while True:
            value = self.connection.recv(1)
            if not value:
                raise RehostError("RSP_EOF", "QEMU GDB response ended early")
            if value == b"#":
                break
            payload.extend(value)
        received_checksum = self._receive_exact(2)
        calculated = f"{sum(payload) & 0xFF:02x}".encode("ascii")
        if received_checksum.lower() != calculated:
            if not self.no_ack:
                self.connection.sendall(b"-")
            raise RehostError("RSP_CHECKSUM", "QEMU GDB response checksum mismatch")
        if not self.no_ack:
            self.connection.sendall(b"+")
        return bytes(payload)

    def _receive_exact(self, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            chunk = self.connection.recv(count - len(chunks))
            if not chunk:
                raise RehostError("RSP_EOF", "QEMU GDB response ended early")
            chunks.extend(chunk)
        return bytes(chunks)
