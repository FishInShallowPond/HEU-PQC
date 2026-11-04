"""v3.2 one-click chip-1 signature proof, fresh chip KEM and chat AEAD.

The signature proves that the current session's signing key is present in chip 1
and was accepted by chip 2. No long-term trust store is used.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from profiles import PROFILES
from protocol import ChipClient, ProtocolError, SerialTransport, normal_order
from text_crypto import TextExchange, TextSecurityError

TIMEZONE = timezone(timedelta(hours=8))
PROTOCOL = b'LC01-COMM-v3.2'
SECRET_COMMANDS = ('读取私钥', '装载私钥', '密钥封装', '密钥解封装')


class AuthenticationRejected(RuntimeError):
    def __init__(self, phase, message):
        super().__init__(message)
        self.phase = phase


class _Stopped(RuntimeError):
    pass


@dataclass(frozen=True)
class CommunicationConfig:
    signature_algorithm: str = 'dilithium2'
    kem_algorithm: str = 'kyber512'
    port1: str = 'COM5'
    port2: str = 'COM6'
    baudrate: int = 38580
    timeout: float = 0.2
    command_timeout: float = 20.0
    command_interval: float = 0.08
    simulate: bool = False

    def validate(self):
        if self.signature_algorithm not in PROFILES or PROFILES[self.signature_algorithm].family != 'signature':
            raise ValueError('签名算法必须是现有数字签名配置')
        if self.kem_algorithm not in PROFILES or PROFILES[self.kem_algorithm].family != 'kem':
            raise ValueError('共享密钥算法必须是现有KEM配置')
        if type(self.simulate) is not bool:
            raise ValueError('simulate必须是布尔值')
        if not self.simulate:
            if (not isinstance(self.port1, str) or not isinstance(self.port2, str)
                    or not self.port1.strip() or not self.port2.strip()
                    or self.port1.strip().casefold() == self.port2.strip().casefold()):
                raise ValueError('请为两块芯片填写不同的COM端口')
        if type(self.baudrate) is not int or self.baudrate <= 0:
            raise ValueError('波特率必须为正整数')
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool)
                   and math.isfinite(v) and v > 0 for v in (self.timeout, self.command_timeout)):
            raise ValueError('串口超时必须为有限正数')
        if (not isinstance(self.command_interval, (int, float)) or isinstance(self.command_interval, bool)
                or not math.isfinite(self.command_interval) or self.command_interval < 0):
            raise ValueError('命令间隔必须为非负有限数')
        return self


def _pack(label, values):
    """Length-prefixed handshake encoding with no ambiguous concatenation."""
    parts = [PROTOCOL, label.encode('utf-8') if isinstance(label, str) else label]
    for value in values:
        if isinstance(value, str):
            value = value.encode('utf-8')
        elif type(value) is bool:
            value = b'\x01' if value else b'\x00'
        elif isinstance(value, int):
            value = value.to_bytes(8, 'big')
        if not isinstance(value, bytes):
            value = str(value).encode('utf-8')
        parts.append(len(value).to_bytes(4, 'big'))
        parts.append(value)
    return b''.join(parts)


def _proof_message(label, context):
    """Existing signature API accepts 1..1000B, excluding multiples of 8."""
    return b'\x31' + hashlib.sha256(_pack(label, (context, b'A>B'))).digest()


class _ChipPair:
    """Two local control UARTs with truthful, secret-reduced trace export."""

    def __init__(self, config: CommunicationConfig, profile, transport_factory,
                 emit, trace_sink):
        self.config = config
        self.profile = profile
        self.emit = emit
        self.trace_sink = trace_sink
        self.transports = []
        self.clients = []
        self.closed = False
        try:
            for chip, port in ((1, config.port1), (2, config.port2)):
                if transport_factory:
                    transport = transport_factory(chip, config, profile)
                elif config.simulate:
                    from simulation import SimulatedTransport
                    transport = SimulatedTransport(profile)
                else:
                    transport = SerialTransport(port.strip(), config.baudrate, config.timeout,
                                                config.command_timeout, config.command_interval)
                self.transports.append(transport)
                transport.connect()
                client = ChipClient(transport, profile, chip, self._trace)
                self.clients.append(client)
                client.initialize()
        except Exception:
            self.close()
            raise

    def _trace(self, item):
        safe = dict(item)
        safe.pop('tx_hex', None)
        safe.pop('rx_hex', None)
        safe.pop('attempted_tx_hex', None)
        safe['tx_bytes'] = len(item.get('tx_hex', '')) // 2
        safe['rx_bytes'] = len(item.get('rx_hex', '')) // 2
        name = item.get('name', '')
        secret = any(token in name for token in SECRET_COMMANDS)
        if secret:
            safe.update(tx_hex='REDACTED', rx_hex='REDACTED', attempted_tx_hex='REDACTED',
                        tx_redacted=True, rx_redacted=True)
            if not item.get('ok'):
                safe['error'] = f'{name}失败；错误内容可能含私钥或共享密钥，已脱敏'
        else:
            safe.update(tx_hex=item.get('tx_hex', ''), rx_hex=item.get('rx_hex', ''),
                        attempted_tx_hex=item.get('attempted_tx_hex', ''),
                        tx_redacted=False, rx_redacted=False)
        self.trace_sink(safe)

    def configure(self, profile):
        for client in self.clients:
            client.configure_profile(profile)
        self.profile = profile
        self.emit({'type': 'log', 'message': f'两块芯片已配置：{profile.name}'})

    def read_private(self, client):
        try:
            return client.read_private_key()
        except Exception as exc:
            raise ProtocolError('读取私钥失败；敏感错误内容已脱敏') from exc

    def write_private(self, client, value):
        try:
            return client.write_private_key(value)
        except Exception as exc:
            raise ProtocolError('装载私钥失败；敏感错误内容已脱敏') from exc

    def encapsulate(self, client):
        try:
            return client.encapsulate()
        except Exception as exc:
            raise ProtocolError('密钥封装失败；共享密钥错误内容已脱敏') from exc

    def decapsulate(self, client, ciphertext):
        try:
            return client.decapsulate(ciphertext)
        except Exception as exc:
            raise ProtocolError('密钥解封装失败；共享密钥错误内容已脱敏') from exc

    def close(self):
        if self.closed:
            return
        self.closed = True
        for transport in self.transports:
            try:
                transport.close()
            except Exception as exc:
                self.emit({'type': 'log', 'message': f'关闭串口失败：{exc}'})


class CommunicationSession:
    """One-click per-session signing proof, KEM, key confirmation and chat."""

    def __init__(self, config: CommunicationConfig, emit=None, transport_factory=None):
        self.config = config.validate()
        self.emit = emit or (lambda event: None)
        self.transport_factory = transport_factory
        self.exchange = None
        self.epochs = []
        self.terminal_error = None
        self.traces = []
        self._payloads = {}
        self._old_sessions = []
        self._closed = False
        self._stop_event = threading.Event()
        self._state_lock = threading.RLock()
        self._operation_lock = threading.Lock()
        self._pair = None
        self.started_at = datetime.now(TIMEZONE).isoformat(timespec='seconds')

    def _trace_append(self, item):
        with self._state_lock:
            self.traces.append(item)

    @property
    def ready(self):
        return not self._closed and self.exchange is not None and self.exchange.ready

    @property
    def closed(self):
        return self._closed

    def _log(self, message):
        line = f'{datetime.now(TIMEZONE).strftime("%H:%M:%S.%f")[:-3]}  {message}'
        try:
            print(line, flush=True)
        except (UnicodeError, OSError):
            pass
        self.emit({'type': 'log', 'message': line})

    def _status(self, stage, message):
        self._log(message)
        self.emit({'type': 'status', 'stage': stage, 'message': message})

    def _check_stop(self):
        if self._stop_event.is_set() or self._closed:
            raise _Stopped('操作已停止')

    def connect(self):
        if not self._operation_lock.acquire(blocking=False):
            raise RuntimeError('通信握手正在执行')
        try:
            self._stop_event.clear()
            with self._state_lock:
                if self._closed:
                    raise RuntimeError('通信会话已关闭')
                if self.exchange is not None:
                    return self
            self._status('connecting', '一键通信：打开两路本地串口…')
            try:
                pair = _ChipPair(self.config, PROFILES[self.config.signature_algorithm],
                                 self.transport_factory, self.emit, self._trace_append)
            except Exception as exc:
                self._fail_from(exc)
                raise RuntimeError(f'打开芯片通信失败：{exc}') from exc
            with self._state_lock:
                if self._closed or self._stop_event.is_set():
                    pair.close()
                    raise RuntimeError('连接已取消')
                self._pair = pair
            try:
                epoch, exchange = self._run_handshake(pair)
                self._check_stop()
                with self._state_lock:
                    if self._closed or self._stop_event.is_set():
                        exchange.close()
                        raise RuntimeError('连接已取消')
                    self.exchange = exchange
                    self.epochs.append(epoch)
                self._status('ready', '芯片1签名已由芯片2验签，KEM与共享密钥确认通过；可以开始文本和图片对话')
                return self
            except Exception as exc:
                self._fail_from(exc)
                raise RuntimeError(str(exc)) from exc
        finally:
            self._operation_lock.release()

    def _run_handshake(self, pair):
        self._check_stop()
        signature = PROFILES[self.config.signature_algorithm]
        kem = PROFILES[self.config.kem_algorithm]
        pair.configure(signature)

        self._status('signature', '生成本次芯片1签名密钥，芯片1签名，芯片2实际验签…')
        pair.clients[0].generate_keypair()
        session_pk_raw = pair.clients[0].read_public_key()
        session_sk_raw = pair.read_private(pair.clients[0])
        handshake_id, challenge = secrets.token_bytes(16), secrets.token_bytes(32)
        signing_context = _pack('session-signing-context', (
            signature.key, self.config.simulate, self.config.kem_algorithm,
            handshake_id, challenge,
            hashlib.sha256(normal_order(session_pk_raw)).digest()))
        proofs = []
        first = self._sign_on_one_verify_on_two(
            pair, session_sk_raw, session_pk_raw, signing_context,
            'session_signing', '芯片1本次签名被芯片2实际拒绝', proofs)
        self._check_stop()
        signing_proof_digest = hashlib.sha256(
            _pack('session-signing-proof', (bytes.fromhex(first['signature_hex']),))).digest()

        self._status('kem', '切换到密钥封装配置，芯片1生成KEM密钥并完成封装/解封装…')
        pair.configure(kem)
        pair.clients[0].generate_keypair()
        pk_raw = pair.clients[0].read_public_key()
        kem_sk_raw = pair.read_private(pair.clients[0])
        pair.clients[1].write_public_key(pk_raw)
        ct_raw, kb_raw = pair.encapsulate(pair.clients[1])
        pair.write_private(pair.clients[0], kem_sk_raw)
        ka_raw = pair.decapsulate(pair.clients[0], ct_raw)
        self._check_stop()
        pk, ct = normal_order(pk_raw), normal_order(ct_raw)
        key_a, key_b = normal_order(ka_raw), normal_order(kb_raw)

        self._status('binding', '切回签名配置，芯片1签名本次KEM结果并由芯片2验签…')
        pair.configure(signature)
        binding_context = _pack('kem-binding-context', (
            signing_context, signing_proof_digest, pk, ct, kem.key))
        second = self._sign_on_one_verify_on_two(
            pair, session_sk_raw, session_pk_raw, binding_context,
            'key_binding', '本次KEM结果签名被芯片2实际拒绝', proofs)
        self._check_stop()
        binding_digest = hashlib.sha256(_pack('verified-kem-binding', (
            binding_context, bytes.fromhex(first['signature_hex']),
            bytes.fromhex(second['signature_hex'])))).digest()
        pair.configure(kem)

        self._status('confirm', '使用各自芯片K确认共享密钥，不比较或替换K1/K2…')
        exchange = TextExchange(key_a, key_b, binding_digest, binding_digest,
                                simulate=self.config.simulate,
                                session_signing_verified=True)
        if not exchange.ready:
            exchange.close()
            raise TextSecurityError('key_confirmation_failed', '双向共享密钥确认失败')
        public_key = normal_order(session_pk_raw)
        public_data = {
            'handshake_id_hex': handshake_id.hex().upper(),
            'challenge_hex': challenge.hex().upper(),
            'kem_algorithm': kem.key, 'kem_pk_hex': pk.hex().upper(),
            'kem_ct_hex': ct.hex().upper(), 'signature_algorithm': signature.key,
            'session_signing_public_key_hex': public_key.hex().upper(),
            'session_signing_public_key_fingerprint': hashlib.sha256(public_key).hexdigest(),
            'kem_private_key_bytes': len(kem_sk_raw),
            'shared_secret_bytes_each': len(key_a),
        }
        epoch = {'number': len(self.epochs) + 1,
                 'time': datetime.now(TIMEZONE).isoformat(timespec='milliseconds'),
                 'session_signing_verified': True,
                 'signing_scope': 'current_session_only',
                 'stored_signing_credentials': False,
                 'proofs': proofs, 'public_data': public_data,
                 'key_confirmation': exchange.export_data()['confirmations'],
                 'direct_k_comparison': False,
                 'mode': 'simulation' if self.config.simulate else 'hardware'}
        return epoch, exchange

    @staticmethod
    def _sign_on_one_verify_on_two(pair, private_raw, public_raw, context, phase,
                                   error_message, proofs):
        message = _proof_message(phase, context)
        pair.write_private(pair.clients[0], private_raw)
        signature_raw = pair.clients[0].sign(message)
        pair.clients[1].write_public_key(public_raw)
        ok, response = pair.clients[1].verify(signature_raw, message)
        proof = {'phase': phase, 'signer': 'A', 'verifier': 'B',
                 'signer_chip': 1, 'verifier_chip': 2,
                 'message_hex': message.hex().upper(),
                 'signature_hex': normal_order(signature_raw).hex().upper(),
                 'response_hex': response.hex().upper(), 'verified': bool(ok)}
        proofs.append(proof)
        if not ok:
            raise AuthenticationRejected(phase, f'{error_message}（返回码{response.hex().upper()}）')
        return proof

    def rekey(self):
        if not self._operation_lock.acquire(blocking=False):
            raise RuntimeError('通信握手或重建密钥正在执行')
        try:
            with self._state_lock:
                if self._closed or self._pair is None:
                    raise RuntimeError('没有可重建密钥的通信会话')
                pair = self._pair
                old = self.exchange
                if old is not None:
                    old.close()
                    self._old_sessions.append(self._session_data(old, session_signing_verified=True))
                    self.exchange = None
            self._status('rekey', '重新建立共享密钥：重新生成签名密钥、验签和芯片KEM…')
            try:
                epoch, exchange = self._run_handshake(pair)
                self._check_stop()
                with self._state_lock:
                    if self._closed or self._stop_event.is_set():
                        exchange.close()
                        raise RuntimeError('重建密钥已取消')
                    self.exchange = exchange
                    self.epochs.append(epoch)
                self._status('ready', '新的共享密钥已确认；旧共享密钥已关闭')
                return self
            except Exception as exc:
                self._fail_from(exc)
                raise RuntimeError(str(exc)) from exc
        finally:
            self._operation_lock.release()

    def send(self, sender, text, fault='none'):
        with self._state_lock:
            if self._closed or self.exchange is None or not self.exchange.ready:
                raise RuntimeError('通信会话未就绪；请先完成一键签名确认和密钥建立')
            exchange = self.exchange
        return exchange.send(sender, text, fault)

    def send_file(self, sender, filename, mime, data, fault='none'):
        with self._state_lock:
            if self._closed or self.exchange is None or not self.exchange.ready:
                raise RuntimeError('通信会话未就绪；请先完成一键签名验签和密钥建立')
            exchange = self.exchange
        record = exchange.send_file(sender, filename, mime, data, fault)
        if record.get('ok'):
            self._payloads[record['payload_id']] = exchange.payload(record['payload_id'])
        return record

    def payload(self, payload_id):
        with self._state_lock:
            if payload_id not in self._payloads:
                raise RuntimeError('文件载荷不在当前通信会话中')
            return bytes(self._payloads[payload_id])

    def release_payload(self, payload_id):
        with self._state_lock:
            self._payloads.pop(payload_id, None)

    def replay_last(self):
        with self._state_lock:
            if self._closed or self.exchange is None:
                raise RuntimeError('通信会话未就绪')
            exchange = self.exchange
        return exchange.replay_last()

    def key_material(self):
        """Return raw demo keys for the local inspector only; never snapshot them."""
        with self._state_lock:
            if self._closed or self.exchange is None or not self.exchange.ready:
                raise TextSecurityError('key_unavailable', '当前通信会话没有已确认的共享密钥')
            exchange = self.exchange
        return exchange.key_material()

    def _session_data(self, exchange, session_signing_verified=True):
        data = exchange.export_data()
        data['session_signing_verified'] = bool(session_signing_verified)
        data['session_signing_scope'] = 'current_session_only'
        data['stored_signing_credentials'] = False
        data['signature_algorithm'] = self.config.signature_algorithm
        return data

    def snapshot(self):
        with self._state_lock:
            sessions = list(copy.deepcopy(self._old_sessions))
            if self.exchange is not None:
                verified = bool(self.epochs and self.epochs[-1].get('session_signing_verified'))
                sessions.append(self._session_data(self.exchange, session_signing_verified=verified))
            return {'version': 'v3.2', 'mode': 'simulation' if self.config.simulate else 'hardware',
                    'ready': self.ready, 'closed': self._closed,
                    'epochs': copy.deepcopy(self.epochs), 'text_sessions': sessions,
                    'terminal_error': copy.deepcopy(self.terminal_error),
                    'signing_scope': 'current_session_only',
                    'stored_signing_credentials': False,
                    'direct_k_comparison': False, 'transport': 'in_process',
                    'network_implemented': False}

    def export(self, directory):
        snapshot = self.snapshot()
        with self._state_lock:
            traces = copy.deepcopy(self.traces)
        destination = Path(directory) / datetime.now(TIMEZONE).strftime('%Y%m%d_%H%M%S_%f')
        destination.mkdir(parents=True, exist_ok=False)
        (destination / 'communication.json').write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2), encoding='utf-8')
        (destination / 'command_trace.json').write_text(
            json.dumps(traces, ensure_ascii=False, indent=2), encoding='utf-8')
        return destination

    def _fail_from(self, exc):
        if isinstance(exc, AuthenticationRejected):
            code = ('key_binding_failed' if exc.phase == 'key_binding'
                    else 'session_signature_failed')
        elif isinstance(exc, TextSecurityError):
            code = getattr(exc, 'code', 'key_confirmation_failed')
        elif isinstance(exc, (ProtocolError, TimeoutError, OSError)):
            code = 'communication_error'
        elif isinstance(exc, _Stopped):
            code = 'stopped'
        else:
            code = 'communication_error'
        with self._state_lock:
            if self.exchange is not None:
                self.exchange.close()
                self.exchange = None
            pair, self._pair = self._pair, None
            self.terminal_error = {'code': code, 'message': str(exc)}
            if not self.epochs:
                self.epochs.append({'number': 1,
                    'time': datetime.now(TIMEZONE).isoformat(timespec='milliseconds'),
                    'session_signing_verified': False,
                    'signing_scope': 'current_session_only',
                    'stored_signing_credentials': False,
                    'public_data': {}, 'proofs': [], 'key_confirmation': {},
                    'direct_k_comparison': False,
                    'mode': 'simulation' if self.config.simulate else 'hardware',
                    'failed_stage': code})
            self._closed = True
            self.exchange = None
            self._payloads.clear()
        if pair is not None:
            pair.close()

    def stop(self):
        self._stop_event.set()

    def close(self):
        self._stop_event.set()
        with self._state_lock:
            self._closed = True
            if self.exchange is not None:
                self.exchange.close()
                verified = bool(self.epochs and self.epochs[-1].get('session_signing_verified'))
                self._old_sessions.append(self._session_data(
                    self.exchange, session_signing_verified=verified))
                self.exchange = None
            self._payloads.clear()
            pair, self._pair = self._pair, None
        if pair is not None:
            pair.close()
