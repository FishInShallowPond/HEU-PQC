"""Strict LC01 UART boundary. All client fields use unmodified wire byte order."""
from __future__ import annotations

import secrets
import time

CLOCK_COMMAND = bytes.fromhex('010610000000000010080000000000FF0000000000')
MAX_PAYLOAD = 65536


class ProtocolError(RuntimeError):
    pass


def frame(head: int, opcode: int, payload: bytes = b'') -> bytes:
    return bytes([head, opcode]) + len(payload).to_bytes(3, 'little') + payload


def normal_order(raw: bytes) -> bytes:
    """Reverse each complete field, not hex characters, words, or CT+K together."""
    return bytes(raw[::-1])


def prepare_message(message: bytes) -> bytes:
    """Same message reversal and 7-byte padding as HEU_py_acvp_pqc_main_v1."""
    if not 1 <= len(message) <= 1000 or len(message) % 8 == 0:
        raise ValueError('签名消息必须为1～1000字节，且字节数不能是8的倍数（沿用芯片测试接口）')
    leading = (-len(message)) % 8
    return b'\x00' * leading + message[::-1] + b'\x00' * (7 - leading)


class SerialTransport:
    """One serial port, single total receive deadline, bounded length-prefixed read."""
    def __init__(self, port, baudrate=38580, timeout=0.2,
                 command_timeout=20.0, command_interval=0.08):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.command_timeout = command_timeout
        self.command_interval = command_interval
        self.serial = None
        self.last_rx = b''
        self.last_tx = b''
        self.write_started = False
        self._last_command = 0.0

    def connect(self):
        import serial
        self.serial = serial.Serial(self.port, self.baudrate, timeout=self.timeout,
                                    write_timeout=self.command_timeout)
        self.serial.reset_input_buffer()
        self.serial.reset_output_buffer()

    def close(self):
        if self.serial is not None:
            self.serial.close()
            self.serial = None

    def _exact(self, size, deadline):
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f'{self.port} 接收超时：本段期望{size}B，已收到{len(data)}B')
            self.serial.timeout = min(self.timeout, remaining)
            chunk = self.serial.read(size - len(data))
            if chunk:
                data.extend(chunk)
                self.last_rx += chunk
        return bytes(data)

    def _reject_pending(self):
        waiting = self.serial.in_waiting
        if waiting:
            self._exact(waiting, time.monotonic() + self.timeout)
            raise ProtocolError(f'{self.port} 收到额外/未请求的串口数据：{self.last_rx.hex().upper()}')

    def _wait_transmitted(self, deadline):
        # pyserial on Windows implements flush() as an unbounded out_waiting
        # loop. Poll it here under the same deadline as the response instead.
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError(f'{self.port} 发送队列排空超时')
            if self.serial.out_waiting == 0:
                return
            time.sleep(0.002)

    def exchange(self, command, *, expect_response=True):
        self.last_rx = b''
        self.last_tx = b''
        self.write_started = False
        if self.serial is None or not self.serial.is_open:
            raise RuntimeError(f'{self.port} 尚未连接')
        delay = self.command_interval - (time.monotonic() - self._last_command)
        if delay > 0:
            time.sleep(delay)
        self._reject_pending()
        deadline = time.monotonic() + self.command_timeout
        try:
            self.write_started = True
            written = self.serial.write(command)
            self.last_tx = command[:written]
            if written != len(command):
                raise ProtocolError(f'串口只发送了{written}/{len(command)}字节')
            self._wait_transmitted(deadline)
            if not expect_response:
                # The legacy clock-enable command has no required response.
                # Drain its optional echo before the next framed command.
                idle_deadline = min(deadline, time.monotonic() + 0.2)
                while time.monotonic() < idle_deadline:
                    waiting = self.serial.in_waiting
                    if waiting:
                        self.last_rx += self.serial.read(waiting)
                        idle_deadline = min(deadline, time.monotonic() + 0.08)
                    time.sleep(0.005)
                return self.last_rx
            header = self._exact(5, deadline)
            length = int.from_bytes(header[2:5], 'little')
            if length > MAX_PAYLOAD:
                raise ProtocolError(f'响应长度{length}B超过上限{MAX_PAYLOAD}B：{header.hex().upper()}')
            payload = self._exact(length, deadline) if length else b''
            self._reject_pending()
            return header + payload
        finally:
            self._last_command = time.monotonic()


class ChipClient:
    def __init__(self, transport, profile, chip, on_trace=None):
        self.transport = transport
        self.profile = profile
        self.chip = chip
        self.on_trace = on_trace or (lambda trace: None)

    def _command(self, name, command, *, size=None, expect_response=True, ack=False, allowed=None):
        start = time.monotonic()
        response = b''
        error = ''
        exchange_returned = False
        try:
            response = self.transport.exchange(command, expect_response=expect_response)
            exchange_returned = True
            if not expect_response:
                return response
            if len(response) < 5:
                raise ProtocolError(f'{name} 响应头不足5B：{response.hex().upper()}')
            expected_head = command[0] | 0x80
            if response[:2] != bytes([expected_head, command[1]]):
                raise ProtocolError(f'{name} 响应类型错误/芯片告警：{response.hex().upper()}')
            length = int.from_bytes(response[2:5], 'little')
            payload = response[5:]
            if length != len(payload):
                raise ProtocolError(f'{name} 长度字段{length}B，实际{len(payload)}B')
            if response == frame(0x81, command[1], b'\x01'):
                raise ProtocolError(f'{name} 芯片告警：{response.hex().upper()}')
            if size is not None and len(payload) != size:
                raise ProtocolError(f'{name} 返回{len(payload)}B，当前通信配置期望{size}B；不进行补齐或截断')
            if ack and payload not in (b'', b'\x00'):
                raise ProtocolError(f'{name} 芯片拒绝命令：{payload.hex().upper()}')
            if allowed is not None and payload not in allowed:
                raise ProtocolError(f'{name} 未知返回码：{payload.hex().upper()}')
            return payload
        except Exception as exc:
            error = str(exc)
            if not response:
                response = getattr(self.transport, 'last_rx', b'')
            raise
        finally:
            actual_tx = getattr(self.transport, 'last_tx', command if exchange_returned else b'')
            if actual_tx == command:
                tx_status = 'complete'
            elif actual_tx:
                tx_status = 'partial'
            elif getattr(self.transport, 'write_started', False) or (not exchange_returned and not hasattr(self.transport, 'last_tx')):
                tx_status = 'unknown'
            else:
                tx_status = 'not_sent'
            self.on_trace({'chip': self.chip, 'name': name,
                           'tx_hex': actual_tx.hex().upper(), 'attempted_tx_hex': command.hex().upper(),
                           'tx_status': tx_status,
                           'rx_hex': response.hex().upper(),
                           'elapsed_ms': round((time.monotonic() - start) * 1000, 2),
                           'ok': not bool(error), 'error': error})

    def initialize(self):
        self._command('开启时钟', CLOCK_COMMAND, expect_response=False)
        self._command('使能算法模块', frame(1, 3, secrets.token_bytes(16)))
        self._command('配置算法', bytes.fromhex(self.profile.config_hex), ack=True)

    def generate_keypair(self):
        self._command('生成密钥', frame(2, 1), ack=True)

    def read_public_key(self):
        return self._command('读取公钥', frame(2, 2), size=self.profile.pk_bytes)

    def read_private_key(self):
        return self._command('读取私钥', frame(2, 3), size=self.profile.sk_bytes)

    def write_public_key(self, value):
        self._check_size(value, self.profile.pk_bytes, '公钥')
        self._command('写入公钥', frame(2, 4, value), ack=True)

    def write_private_key(self, value):
        self._check_size(value, self.profile.sk_bytes, '私钥')
        self._command('芯片1装载私钥', frame(2, 5, value), ack=True)

    def encapsulate(self):
        payload = self._command('密钥封装', frame(2, 8), size=self.profile.ct_bytes + self.profile.k_bytes)
        return payload[:self.profile.ct_bytes], payload[self.profile.ct_bytes:]

    def decapsulate(self, ciphertext):
        self._check_size(ciphertext, self.profile.ct_bytes, '密文')
        return self._command('密钥解封装', frame(2, 9, ciphertext), size=self.profile.k_bytes)

    def sign(self, message):
        return self._command('数字签名', frame(2, 11, prepare_message(message)), size=self.profile.signature_bytes)

    def verify(self, signature, message):
        self._check_size(signature, self.profile.signature_bytes, '签名')
        payload = len(signature).to_bytes(2, 'little') + signature + prepare_message(message)
        result = self._command('签名验证', frame(2, 10, payload), size=1, allowed=(b'\x00', b'\x01'))
        return result == b'\x00', result

    @staticmethod
    def _check_size(value, expected, name):
        if len(value) != expected:
            raise ProtocolError(f'{name}为{len(value)}B，期望{expected}B')
