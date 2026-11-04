"""Explicit protocol-only simulation. NOT a PQC implementation or test oracle.

Hash constructions below merely allow previewing the UI and transfer workflow.
Real mode always instantiates SerialTransport and never falls back here.
"""
import hashlib
import secrets

from protocol import CLOCK_COMMAND, ProtocolError, frame


def expand(label, data, length):
    return hashlib.shake_256(label + data).digest(length)


class SimulatedTransport:
    def __init__(self, profile):
        self.profile = profile
        self.closed = False
        self.pk = self.sk = b''
        self.last_rx = b''

    def connect(self):
        self.closed = False

    def close(self):
        self.closed = True

    def configure_profile(self, profile):
        """Model a successful firmware profile switch in explicit simulation only."""
        self.profile = profile

    def exchange(self, command, **kwargs):
        if self.closed:
            raise RuntimeError('模拟连接已关闭')
        if command == CLOCK_COMMAND:
            return b''
        payload = command[5:]
        if len(payload) != int.from_bytes(command[2:5], 'little'):
            raise ProtocolError('模拟协议命令长度错误')
        opcode = command[1]
        p = self.profile
        if command[0] == 1:
            answer = payload
        elif opcode == 0:
            if command.hex().upper() != p.config_hex:
                raise ProtocolError('模拟算法配置错误')
            answer = b'\x00'
        elif opcode == 1:
            self.pk = secrets.token_bytes(p.pk_bytes)
            self.sk = self.pk + secrets.token_bytes(p.sk_bytes - p.pk_bytes)
            answer = b'\x00'
        elif opcode == 2:
            answer = self.pk
        elif opcode == 3:
            answer = self.sk
        elif opcode == 4:
            self.pk = payload
            answer = b'\x00'
        elif opcode == 5:
            self.sk = payload
            answer = b'\x00'
        elif opcode == 8:
            ciphertext = secrets.token_bytes(p.ct_bytes)
            answer = ciphertext + expand(b'demo-k', self.pk + ciphertext, p.k_bytes)
        elif opcode == 9:
            answer = expand(b'demo-k', self.sk[:p.pk_bytes] + payload, p.k_bytes)
        elif opcode == 11:
            answer = expand(b'demo-sign', self.sk[:p.pk_bytes] + payload, p.signature_bytes)
        elif opcode == 10:
            size = int.from_bytes(payload[:2], 'little')
            signature, message = payload[2:2 + size], payload[2 + size:]
            expected = expand(b'demo-sign', self.pk + message, p.signature_bytes)
            answer = b'\x00' if secrets.compare_digest(signature, expected) else b'\x01'
        else:
            raise ProtocolError(f'模拟协议不支持命令{opcode}')
        self.last_rx = frame(command[0] | 0x80, opcode, answer)
        return self.last_rx
