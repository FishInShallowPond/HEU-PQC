"""Real software AEAD over independently supplied endpoint secrets.

The coordinator delivers bytes in-process. This is a demonstration record
protocol, not a long-term trust store, TLS, or a PQC implementation.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import secrets
import struct
import threading
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HEADER = struct.Struct('!4sBBB16sQI')
MAX_TEXT_BYTES = 65536
MAX_FILE_BYTES = 16 * 1024 * 1024
FILE_CHUNK_BYTES = 60 * 1024
MAX_RECORDS = 1 << 20
MAX_SESSION_BYTES = 64 * 1024 * 1024
RECORD_TEXT = 1
RECORD_FILE_BEGIN = 2
RECORD_FILE_CHUNK = 3
RECORD_FILE_END = 4
_RECORD_TYPES = {RECORD_TEXT, RECORD_FILE_BEGIN, RECORD_FILE_CHUNK, RECORD_FILE_END}
_LABELS = {'A': b'A>B', 'B': b'B>A'}

_FILE_BEGIN = struct.Struct('!B16sQ32sIIHH')
_FILE_CHUNK = struct.Struct('!16sIQ')
_FILE_END = struct.Struct('!16sIQ32s')


class TextSecurityError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def transcript_hash(algorithm: str, pk: bytes, ct: bytes) -> bytes:
    parts = (algorithm.encode('utf-8'), pk, ct)
    return hashlib.sha256(b'LC01-KEM-TRANSCRIPT-v1\x00' + b''.join(
        len(part).to_bytes(4, 'big') + part for part in parts)).digest()


def _file_metadata(filename, mime):
    if not isinstance(filename, str) or not filename or len(filename.encode('utf-8')) > 255:
        raise ValueError('文件名必须为1..255字节UTF-8文本')
    if any(character in filename for character in ('/', '\\', '\x00')) or filename in ('.', '..'):
        raise ValueError('文件名不能含路径分隔符')
    if (not isinstance(mime, str) or not mime or len(mime) > 127
            or '/' not in mime or any(ord(character) < 32 or ord(character) > 126 for character in mime)):
        raise ValueError('MIME类型格式无效')
    return filename.encode('utf-8'), mime.encode('ascii')


def _take_prefixed(data, offset, size_struct):
    if offset + size_struct.size > len(data):
        raise TextSecurityError('invalid_file_record', '文件元数据长度不足')
    return size_struct.unpack_from(data, offset), offset + size_struct.size


def _take_bytes(data, offset, length):
    if length < 0 or offset + length > len(data):
        raise TextSecurityError('invalid_file_record', '文件元数据长度截断')
    return data[offset:offset + length], offset + length


class SecureEndpoint:
    """Single-caller record state; holds only its own derived key context."""

    def __init__(self, role, secret, session_id, salt, transcript):
        if (role not in _LABELS or not isinstance(secret, bytes) or len(secret) != 32
                or not isinstance(session_id, bytes) or len(session_id) != 16
                or not isinstance(salt, bytes) or len(salt) != 32
                or not isinstance(transcript, bytes) or len(transcript) != 32):
            raise ValueError('端点要求A/B角色、32B芯片K、16B会话编号、32B salt及32B握手摘要')
        self.role = role
        self.session_id = session_id
        self.transcript = transcript
        self._context = b'LC01-TEXT-v1\x00' + session_id + transcript
        self._tx_label = _LABELS[role]
        self._rx_label = _LABELS['B' if role == 'A' else 'A']

        def derive(label, purpose, size):
            return HKDF(algorithm=hashes.SHA256(), length=size, salt=salt,
                        info=self._context + b'\x00' + label + b'/' + purpose).derive(secret)

        self._tx_key = derive(self._tx_label, b'aes', 32)
        self._rx_key = derive(self._rx_label, b'aes', 32)
        self._tx_cipher = AESGCM(self._tx_key)
        self._rx_cipher = AESGCM(self._rx_key)
        self._tx_prefix = derive(self._tx_label, b'nonce', 4)
        self._rx_prefix = derive(self._rx_label, b'nonce', 4)
        self._tx_confirm = derive(self._tx_label, b'confirm', 32)
        self._rx_confirm = derive(self._rx_label, b'confirm', 32)
        self._tx_sequence = self._rx_sequence = 0
        self._tx_bytes = self._rx_bytes = 0
        self.confirmed = False
        self.closed = False

    def _active(self, *, confirmation=False):
        if self.closed:
            raise TextSecurityError('closed', '安全会话已关闭，请重新建立会话')
        if not confirmation and not self.confirmed:
            raise TextSecurityError('not_confirmed', '尚未通过共享密钥确认，禁止业务收发')

    def confirmation(self):
        self._active(confirmation=True)
        return hmac.digest(self._tx_confirm,
                           b'LC01-FINISHED-v1\x00' + self._context + b'\x00' + self._tx_label, 'sha256')

    def verify_confirmation(self, token):
        self._active(confirmation=True)
        expected = hmac.digest(self._rx_confirm,
                               b'LC01-FINISHED-v1\x00' + self._context + b'\x00' + self._rx_label, 'sha256')
        if not isinstance(token, bytes) or not hmac.compare_digest(expected, token):
            self.close()
            raise TextSecurityError('confirmation_failed', '共享密钥确认失败：本地K或握手记录与对端不一致')
        self.confirmed = True

    def encrypt(self, plaintext: bytes, record_type=RECORD_TEXT) -> bytes:
        self._active()
        if record_type not in _RECORD_TYPES:
            raise ValueError('未知记录类型')
        if not isinstance(plaintext, bytes) or len(plaintext) > MAX_TEXT_BYTES:
            raise ValueError(f'每条文本编码后最多{MAX_TEXT_BYTES}字节')
        if self._tx_sequence >= MAX_RECORDS or self._tx_bytes + len(plaintext) > MAX_SESSION_BYTES:
            self.close()
            raise TextSecurityError('key_limit', '已达到业务密钥使用限额，请重新建立会话')
        sequence = self._tx_sequence
        header = HEADER.pack(b'LC3T', 1, record_type, 0 if self.role == 'A' else 1,
                             self.session_id, sequence, len(plaintext) + 16)
        nonce = self._tx_prefix + sequence.to_bytes(8, 'big')
        # Reserve the nonce before encryption; an unexpected library error cannot
        # lead to retrying an already-used nonce under this key.
        self._tx_sequence += 1
        self._tx_bytes += len(plaintext)
        try:
            return header + self._tx_cipher.encrypt(nonce, plaintext, header)
        except Exception:
            self.close()
            raise

    def decrypt(self, packet: bytes, expected_type=RECORD_TEXT) -> bytes:
        self._active()
        try:
            if not isinstance(packet, bytes) or len(packet) < HEADER.size + 16:
                raise TextSecurityError('invalid_record', '报文不足完整头和认证标签长度')
            magic, version, kind, direction, sid, sequence, size = HEADER.unpack(packet[:HEADER.size])
            if magic != b'LC3T' or version != 1 or kind not in _RECORD_TYPES:
                raise TextSecurityError('invalid_record', '报文魔数、版本或类型无效')
            if kind != expected_type:
                raise TextSecurityError('invalid_record', '报文记录类型与当前文件状态不符')
            if sid != self.session_id:
                raise TextSecurityError('wrong_session', '报文不属于当前安全会话')
            if direction != (1 if self.role == 'A' else 0):
                raise TextSecurityError('wrong_direction', '报文方向错误，拒绝反射消息')
            if size < 16 or size > MAX_TEXT_BYTES + 16 or size != len(packet) - HEADER.size:
                raise TextSecurityError('invalid_record', '密文长度无效，可能截断或存在多余数据')
            if sequence != self._rx_sequence:
                raise TextSecurityError('sequence_error', f'拒绝重放或乱序：期望序号{self._rx_sequence}，收到{sequence}')
            if sequence >= MAX_RECORDS or self._rx_bytes + size - 16 > MAX_SESSION_BYTES:
                raise TextSecurityError('key_limit', '已达到接收密钥使用限额，请重新建立会话')
            nonce = self._rx_prefix + sequence.to_bytes(8, 'big')
            plaintext = self._rx_cipher.decrypt(nonce, packet[HEADER.size:], packet[:HEADER.size])
            self._rx_sequence += 1
            self._rx_bytes += len(plaintext)
            return plaintext
        except InvalidTag as exc:
            self.close()
            raise TextSecurityError('authentication_failed', 'AES-GCM认证失败：拒绝交付明文') from exc
        except TextSecurityError:
            self.close()
            raise
        except Exception:
            self.close()
            raise

    def close(self):
        self.closed = True
        self.confirmed = False
        self._tx_cipher = self._rx_cipher = None
        self._tx_key = self._rx_key = b''
        self._tx_confirm = self._rx_confirm = b''
        self._tx_prefix = self._rx_prefix = b''


class TextExchange:
    """Local delivery coordinator. Never substitutes one endpoint's K for another."""

    def __init__(self, key_a, key_b, transcript_a, transcript_b, simulate=False,
                 session_signing_verified=False):
        self._lock = threading.RLock()
        self.session_id = secrets.token_bytes(16)
        self.salt = secrets.token_bytes(32)
        self.simulate = bool(simulate)
        self.session_signing_verified = bool(session_signing_verified)
        self.history = []
        self._last = None
        self._payloads = {}
        self._closed = False
        self._terminal_error = None
        self._k_a = bytes(key_a)
        self._k_b = bytes(key_b)
        self._a = SecureEndpoint('A', key_a, self.session_id, self.salt, transcript_a)
        self._b = SecureEndpoint('B', key_b, self.session_id, self.salt, transcript_b)
        self._confirmations = {}
        tokens = {'A': self._a.confirmation(), 'B': self._b.confirmation()}
        for role, endpoint, peer in (('A', self._a, 'B'), ('B', self._b, 'A')):
            try:
                endpoint.verify_confirmation(tokens[peer])
                self._confirmations[role] = {'ok': True, 'message': '共享密钥确认通过'}
            except TextSecurityError as exc:
                self._confirmations[role] = {'ok': False, 'message': str(exc)}
        self._tokens = {role: value.hex().upper() for role, value in tokens.items()}
        if not all(value['ok'] for value in self._confirmations.values()):
            self.close()

    @property
    def ready(self):
        return not self._closed and self._a.confirmed and self._b.confirmed

    def _require_ready(self):
        if not self.ready:
            raise TextSecurityError('not_ready', '安全会话未就绪或已终止，请检查密钥确认或重新建立会话')

    def send(self, sender, text, fault='none'):
        with self._lock:
            self._require_ready()
            if sender not in _LABELS or not isinstance(text, str):
                raise ValueError('请选择A/B发送端并输入文本')
            if fault not in ('none', 'ciphertext', 'tag', 'header'):
                raise ValueError('未知故障选项')
            plaintext = text.encode('utf-8')
            if len(plaintext) > MAX_TEXT_BYTES:
                raise ValueError(f'每条文本编码后最多{MAX_TEXT_BYTES}字节')
            source = self._a if sender == 'A' else self._b
            try:
                packet = source.encrypt(plaintext)
            except TextSecurityError:
                self.close()
                raise
            except Exception as exc:
                self._terminal_error = {'code': 'encryption_error', 'sender': sender, 'message': str(exc)}
                self.close()
                raise
            actual = bytearray(packet)
            if fault == 'ciphertext':
                # Empty plaintext has only a tag; mutate that instead.
                actual[HEADER.size] ^= 1
            elif fault == 'tag':
                actual[-1] ^= 1
            elif fault == 'header':
                # Corrupt type, a field authenticated as part of AAD.
                actual[5] ^= 1
            self._last = (sender, packet, bytes(actual), RECORD_TEXT)
            return self._deliver(sender, packet, bytes(actual), text, fault, False)

    def replay_last(self):
        with self._lock:
            self._require_ready()
            if self._last is None:
                raise ValueError('尚无可以重放的业务报文')
            if self._last[3] != RECORD_TEXT:
                raise ValueError('当前上一报文是文件记录，请在后续文本报文上演示重放')
            sender, original, actual, _ = self._last
            return self._deliver(sender, original, actual, None, 'replay', True)

    @property
    def can_replay(self):
        return self.ready and self._last is not None and self._last[3] == RECORD_TEXT

    def send_file(self, sender, filename, mime, data, fault='none'):
        """Send one authenticated binary file as BEGIN + CHUNK* + END records."""
        with self._lock:
            self._require_ready()
            if sender not in _LABELS:
                raise ValueError('请选择A/B发送端')
            if not isinstance(data, bytes):
                raise ValueError('文件内容必须是bytes')
            if len(data) > MAX_FILE_BYTES:
                raise ValueError(f'单个文件最多{MAX_FILE_BYTES}字节')
            filename_b, mime_b = _file_metadata(filename, mime)
            faults = {'none', 'file_chunk_tag', 'file_chunk_ciphertext', 'file_digest',
                      'file_drop', 'file_reorder', 'file_drop_end', 'file_end_tag'}
            if fault not in faults:
                raise ValueError('未知图片/文件故障选项')
            transfer_id = secrets.token_bytes(16)
            digest = hashlib.sha256(data).digest()
            chunk_count = (len(data) + FILE_CHUNK_BYTES - 1) // FILE_CHUNK_BYTES
            begin = _FILE_BEGIN.pack(1, transfer_id, len(data), digest,
                                     FILE_CHUNK_BYTES, chunk_count,
                                     len(mime_b), len(filename_b)) + mime_b + filename_b
            clear_records = [(RECORD_FILE_BEGIN, begin)]
            for index in range(chunk_count):
                chunk = data[index * FILE_CHUNK_BYTES:(index + 1) * FILE_CHUNK_BYTES]
                payload = _FILE_CHUNK.pack(transfer_id, index, index * FILE_CHUNK_BYTES) + chunk
                clear_records.append((RECORD_FILE_CHUNK, payload))
            end_digest = digest
            if fault == 'file_digest':
                end_digest = bytes([digest[0] ^ 1]) + digest[1:]
            clear_records.append((RECORD_FILE_END, _FILE_END.pack(
                transfer_id, chunk_count, len(data), end_digest)))

            source = self._a if sender == 'A' else self._b
            receiver = self._b if sender == 'A' else self._a
            packets = []
            for record_type, payload in clear_records:
                packet = source.encrypt(payload, record_type)
                packets.append((record_type, packet))

            delivery = list(packets)
            if fault == 'file_drop':
                drop_index = next((i for i, item in enumerate(delivery)
                                   if item[0] == RECORD_FILE_CHUNK), None)
                if drop_index is not None:
                    delivery.pop(drop_index)
            elif fault == 'file_reorder':
                chunks = [i for i, item in enumerate(delivery) if item[0] == RECORD_FILE_CHUNK]
                if len(chunks) >= 2:
                    first, second = chunks[:2]
                    delivery[first], delivery[second] = delivery[second], delivery[first]
            elif fault == 'file_drop_end':
                delivery = [item for item in delivery if item[0] != RECORD_FILE_END]

            record = {'time': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
                      'kind': 'file', 'sender': sender,
                      'receiver': 'B' if sender == 'A' else 'A',
                      'file_name': filename, 'mime': mime, 'file_size': len(data),
                      'sha256': digest.hex(), 'chunk_count': chunk_count,
                      'first_sequence': None, 'last_sequence': None,
                      'fault': fault, 'replay': False, 'ok': False,
                      'error_code': '', 'message': '', 'packet_summaries': [],
                      'packet_details': []}
            state = None
            received = bytearray()
            end_seen = False
            last_actual = None
            chunk_index = -1
            try:
                for position, (record_type, original) in enumerate(delivery):
                    actual = bytearray(original)
                    if record_type == RECORD_FILE_END and fault == 'file_end_tag':
                        actual[-1] ^= 1
                    if record_type == RECORD_FILE_CHUNK:
                        if fault == 'file_chunk_tag':
                            actual[-1] ^= 1
                        elif fault == 'file_chunk_ciphertext':
                            actual[HEADER.size] ^= 1
                    actual = bytes(actual)
                    last_actual = actual
                    plain = receiver.decrypt(actual, expected_type=record_type)
                    _, _, _, _, _, sequence, _ = HEADER.unpack(actual[:HEADER.size])
                    record['packet_summaries'].append({
                        'sequence': sequence, 'type': record_type,
                        'header_hex': actual[:HEADER.size].hex().upper(),
                        'encrypted_bytes': len(actual) - HEADER.size,
                        'faulted': actual != original})
                    if record_type == RECORD_FILE_CHUNK:
                        chunk_index += 1
                    detail = {
                        'sequence': sequence, 'type': record_type,
                        'block_index': chunk_index if record_type == RECORD_FILE_CHUNK else None,
                        'nonce_hex': (source._tx_prefix + sequence.to_bytes(8, 'big')).hex().upper(),
                        'header_hex': actual[:HEADER.size].hex().upper(),
                        'ciphertext_hex': actual[HEADER.size:-16].hex().upper(),
                        'tag_hex': actual[-16:].hex().upper(),
                        'faulted': actual != original}
                    if actual != original:
                        detail['delivered_packet_hex'] = actual.hex().upper()
                    record['packet_details'].append(detail)
                    if record['first_sequence'] is None:
                        record['first_sequence'] = sequence
                    record['last_sequence'] = sequence
                    if record_type == RECORD_FILE_BEGIN:
                        if state is not None:
                            raise TextSecurityError('invalid_file_record', '重复的文件开始记录')
                        version, received_id, total, declared_digest, chunk_size, declared_chunks, mime_len, name_len = _FILE_BEGIN.unpack_from(plain)
                        strings_start = _FILE_BEGIN.size
                        if version != 1 or chunk_size != FILE_CHUNK_BYTES:
                            raise TextSecurityError('invalid_file_record', '文件元数据版本或分块大小无效')
                        if total > MAX_FILE_BYTES or total < 0 or declared_chunks != (total + chunk_size - 1) // chunk_size:
                            raise TextSecurityError('invalid_file_record', '文件长度或分块数无效')
                        mime_raw, after_mime = _take_bytes(plain, strings_start, mime_len)
                        name_raw, end_offset = _take_bytes(plain, after_mime, name_len)
                        if end_offset != len(plain):
                            raise TextSecurityError('invalid_file_record', '文件开始记录含多余数据')
                        try:
                            received_mime = mime_raw.decode('ascii')
                            received_name = name_raw.decode('utf-8')
                        except UnicodeError as exc:
                            raise TextSecurityError('invalid_file_record', '文件名或MIME编码无效') from exc
                        _file_metadata(received_name, received_mime)
                        state = {'id': received_id, 'total': total,
                                 'digest': declared_digest, 'chunk_size': chunk_size,
                                 'chunk_count': declared_chunks, 'mime': received_mime,
                                 'name': received_name, 'chunks': 0}
                    elif record_type == RECORD_FILE_CHUNK:
                        if state is None or end_seen:
                            raise TextSecurityError('invalid_file_record', '未开始或已结束的文件块')
                        if len(plain) < _FILE_CHUNK.size:
                            raise TextSecurityError('invalid_file_record', '文件块头不完整')
                        received_id, index, offset = _FILE_CHUNK.unpack_from(plain)
                        chunk = plain[_FILE_CHUNK.size:]
                        if received_id != state['id']:
                            raise TextSecurityError('wrong_file', '文件块编号与当前传输不符')
                        if index != state['chunks'] or offset != len(received):
                            raise TextSecurityError('file_order_error', '文件块重复、乱序或偏移错误')
                        if not chunk or len(chunk) > state['chunk_size']:
                            raise TextSecurityError('invalid_file_record', '文件块长度无效')
                        if len(received) + len(chunk) > state['total']:
                            raise TextSecurityError('invalid_file_record', '文件块超过声明总长度')
                        received.extend(chunk)
                        state['chunks'] += 1
                    else:
                        if state is None or end_seen:
                            raise TextSecurityError('invalid_file_record', '无对应开始记录的文件结束')
                        received_id, declared_chunks, total, declared_digest = _FILE_END.unpack(plain)
                        if (received_id != state['id'] or declared_chunks != state['chunk_count']
                                or total != state['total'] or state['chunks'] != state['chunk_count']
                                or len(received) != state['total']):
                            raise TextSecurityError('incomplete_file', '文件结束记录与已收块/长度不一致')
                        actual_digest = hashlib.sha256(received).digest()
                        if (not hmac.compare_digest(declared_digest, actual_digest)
                                or not hmac.compare_digest(state['digest'], actual_digest)):
                            raise TextSecurityError('file_digest_mismatch', '整文件SHA-256不一致，拒绝交付')
                        end_seen = True
                if not end_seen:
                    raise TextSecurityError('incomplete_file', '文件传输未收到有效结束记录')
            except TextSecurityError as exc:
                received.clear()
                record.update(error_code=exc.code, message=str(exc))
                self.history.append(record)
                self._last = (sender, packets[-1][1], last_actual or packets[-1][1],
                              packets[-1][0])
                self.close()
                return copy.deepcopy(record)
            except Exception as exc:
                received.clear()
                self._terminal_error = {'code': 'file_internal_error', 'sender': sender,
                                        'message': str(exc)}
                record.update(error_code='internal_error',
                              message='文件处理内部异常，未交付：' + str(exc))
                self.history.append(record)
                self.close()
                raise

            payload_id = transfer_id.hex().upper()
            self._payloads[payload_id] = bytes(received)
            self._last = (sender, packets[-1][1], last_actual or packets[-1][1],
                          packets[-1][0])
            record.update(ok=True, payload_id=payload_id,
                          received_sha256=hashlib.sha256(received).hexdigest(),
                          message=f'文件认证解密完成并通过SHA-256校验（{chunk_count}块）')
            self.history.append(record)
            return copy.deepcopy(record)

    def payload(self, payload_id):
        """Return verified binary payload for local chat preview/download."""
        if not isinstance(payload_id, str) or payload_id not in self._payloads:
            raise TextSecurityError('payload_unavailable', '没有通过完整性校验的本地文件载荷')
        return bytes(self._payloads[payload_id])

    def key_material(self):
        """Return session keys only for the local key inspector; never exported."""
        with self._lock:
            if self._closed or not self.ready:
                raise TextSecurityError('key_unavailable', '当前通信会话没有可显示的已确认密钥')
            return {
                'k_a_hex': self._k_a.hex().upper(),
                'k_b_hex': self._k_b.hex().upper(),
                'k_a_fingerprint': hashlib.sha256(self._k_a).hexdigest().upper(),
                'k_b_fingerprint': hashlib.sha256(self._k_b).hexdigest().upper(),
                'a_to_b_aes_hex': self._a._tx_key.hex().upper(),
                'b_to_a_aes_hex': self._b._tx_key.hex().upper(),
                'a_to_b_aes_fingerprint': hashlib.sha256(self._a._tx_key).hexdigest().upper(),
                'b_to_a_aes_fingerprint': hashlib.sha256(self._b._tx_key).hexdigest().upper(),
                'session_id_hex': self.session_id.hex().upper(),
                'both_directions_confirmed': all(item['ok'] for item in self._confirmations.values()),
            }

    def _deliver(self, sender, original, actual, text, fault, replay):
        receiver = self._b if sender == 'A' else self._a
        source = self._a if sender == 'A' else self._b
        _, _, _, _, _, sequence, _ = HEADER.unpack(original[:HEADER.size])
        record = {'time': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
                  'kind': 'text',
                  'sender': sender, 'receiver': 'B' if sender == 'A' else 'A',
                  'sequence': sequence, 'fault': fault, 'replay': replay,
                  'sent_text': text, 'received_text': None, 'ok': False,
                  'error_code': '', 'message': '',
                  'nonce_hex': (source._tx_prefix + sequence.to_bytes(8, 'big')).hex().upper(),
                  'header_hex': original[:HEADER.size].hex().upper(),
                  'ciphertext_hex': original[HEADER.size:-16].hex().upper(),
                  'tag_hex': original[-16:].hex().upper(),
                  'original_packet_hex': original.hex().upper(),
                  'delivered_packet_hex': actual.hex().upper()}
        try:
            plain = receiver.decrypt(actual)
            received = plain.decode('utf-8')
            record.update(ok=True, received_text=received, message='认证解密通过，已交付文本')
        except TextSecurityError as exc:
            record.update(error_code=exc.code, message=str(exc))
            self.close()
        except UnicodeDecodeError:
            record.update(error_code='invalid_utf8', message='认证后的负载不是有效UTF-8文本，拒绝交付')
            self.close()
        except Exception as exc:
            self._terminal_error = {'code': 'decryption_error', 'sender': sender, 'message': str(exc)}
            record.update(error_code='internal_error', message='解密处理内部异常，未交付明文：' + str(exc))
            self.history.append(record)
            self.close()
            raise
        self.history.append(record)
        return copy.deepcopy(record)

    def export_data(self):
        with self._lock:
            records = []
            for item in self.history:
                exported = {key: copy.deepcopy(value) for key, value in item.items()
                            if key != 'packet_details'}
                exported['packet_details_available_in_ui'] = bool(item.get('packet_details'))
                records.append(exported)
            return {'session_id': self.session_id.hex().upper(), 'salt_hex': self.salt.hex().upper(),
                    'algorithm': 'HKDF-SHA-256 / AES-256-GCM / HMAC-SHA-256',
                    'transport': 'in_process',
                    'session_signing_verified': self.session_signing_verified,
                    'kem_source': 'protocol_simulation' if self.simulate else 'chip_output',
                    'software_crypto': 'real_cryptography_library', 'ready': self.ready,
                    'closed': self._closed,
                    'terminal_error': copy.deepcopy(self._terminal_error),
                    'transcript_a_hex': self._a.transcript.hex().upper(),
                    'transcript_b_hex': self._b.transcript.hex().upper(),
                    'confirmations': copy.deepcopy(self._confirmations),
                    'confirmation_tokens_hex': dict(self._tokens),
                    'limits': {'text_bytes': MAX_TEXT_BYTES, 'records_per_direction': MAX_RECORDS,
                               'plaintext_bytes_per_direction': MAX_SESSION_BYTES,
                               'file_bytes': MAX_FILE_BYTES, 'file_chunk_bytes': FILE_CHUNK_BYTES},
                    'records': records}

    def close(self):
        with self._lock:
            self._closed = True
            self._a.close()
            self._b.close()
            self._k_a = self._k_b = b''
            self._payloads.clear()
