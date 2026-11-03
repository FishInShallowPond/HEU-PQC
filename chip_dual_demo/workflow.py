"""Two-chip session, truthful results, display events and inspectable exports."""
from __future__ import annotations

import json
import math
import secrets
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType

from profiles import PROFILES
from protocol import ChipClient, SerialTransport, normal_order, prepare_message

CHINA_TIME = timezone(timedelta(hours=8))
TRANSFER_ENDPOINTS = {'pk': (1, 2), 'ct': (2, 1), 'signature': (1, 2), 'message': (1, 2)}
COMPARISON_PAIRS = (('pk', 'received_pk'), ('ct', 'received_ct'),
                    ('signature', 'received_signature'), ('message', 'received_message'), ('k1', 'k2'))


def diff_offsets(left: bytes, right: bytes) -> list[int]:
    """Zero-based offsets in normal byte order, including unmatched tail bytes."""
    return [i for i in range(max(len(left), len(right))) if left[i:i + 1] != right[i:i + 1]]


@dataclass(frozen=True)
class DemoConfig:
    algorithm: str = 'kyber512'
    port1: str = 'COM5'
    port2: str = 'COM6'
    baudrate: int = 38580
    timeout: float = 0.2
    command_timeout: float = 20.0
    command_interval: float = 0.08
    simulate: bool = False
    message: bytes = b'HEU dual chip demo'
    pause_before_transfer: bool = False


class DemoSession:
    def __init__(self, config: DemoConfig, emit=None, transport_factory=None):
        if config.algorithm not in PROFILES:
            raise ValueError(f'未知算法：{config.algorithm}')
        self.config = config
        self.profile = PROFILES[config.algorithm]
        if not config.simulate:
            if not config.port1.strip() or not config.port2.strip():
                raise ValueError('请分别填写两块芯片的串口')
            if config.port1.strip().casefold() == config.port2.strip().casefold():
                raise ValueError('两块芯片必须使用不同的串口')
        if config.baudrate <= 0:
            raise ValueError('波特率必须大于0')
        if not all(math.isfinite(v) and v > 0 for v in (config.timeout, config.command_timeout)):
            raise ValueError('串口和命令超时必须是大于0的有限数值')
        if not math.isfinite(config.command_interval) or config.command_interval < 0:
            raise ValueError('命令间隔必须是非负有限数值')
        if self.profile.family == 'signature':
            prepare_message(config.message)
        self.emit = emit or (lambda event: None)
        self.transport_factory = transport_factory
        self.fields = {}
        self.raw = {}
        self._pending = {}
        self.pending_transfers = MappingProxyType(self._pending)
        self._delivered = {}
        self._sent = {}
        self._send_attempts = {}
        self.edit_history = []
        self.waiting_for_transfer = None
        self._operation_lock = threading.Lock()
        self.trace = []
        self.logs = []
        self.result = None
        self.next_step = 0
        self.clients = []
        self._transports = []
        self._stopped = threading.Event()
        self._closed = False
        self._failed = False
        self.started_at = datetime.now(CHINA_TIME).isoformat(timespec='seconds')
        self.steps = ['连接并初始化两块芯片', '芯片1生成公私钥']
        if self.profile.family == 'kem':
            self.steps += ['公钥：芯片1 → 芯片2', '芯片2封装，生成密文与K2', '密文：芯片2 → 芯片1，解封装生成K1', '比较K1与K2']
            self._actions = [self._initialize, self._keygen, self._transfer_pk, self._encaps, self._decaps, self._compare]
        else:
            self.steps += ['芯片1对消息签名', '公钥、消息、签名：芯片1 → 芯片2', '芯片2验证签名']
            self._actions = [self._initialize, self._keygen, self._sign, self._transfer_signature, self._verify]
        self._log(('流程模拟（仅协议替身，不验证密码算法）' if config.simulate else '真实双芯片硬件模式') + f' / {self.profile.name}')
        self._log('数据显示为正常字节序；芯片之间转发原始字段，原始TX/RX保留在命令记录中')
        if self.profile.family == 'kem':
            self._log('沿用既有芯片通信配置：PK=800B、SK=1632B、CT=768B、K=32B；所有字段不补齐、不截断')

    def _log(self, message):
        line = f'{datetime.now(CHINA_TIME).strftime("%H:%M:%S.%f")[:-3]}  {message}'
        self.logs.append(line)
        try:
            print(line, flush=True)
        except (UnicodeError, OSError):
            pass
        self.emit({'type': 'log', 'message': line})

    def _trace(self, item):
        self.trace.append(item)
        attempted = bytes.fromhex(item.get('attempted_tx_hex', item['tx_hex']))
        names = {4: ('pk',), 9: ('ct',), 10: ('signature', 'message')}
        if len(attempted) >= 5 and attempted[0] == 2 and attempted[1] in names:
            for name in names[attempted[1]]:
                self._send_attempts[name] = {'send_status': item.get('tx_status', 'unknown'),
                                             'tx_command_hex': item['tx_hex'],
                                             'attempted_command_hex': attempted.hex().upper()}
                if item.get('tx_status') == 'complete':
                    self._sent[name] = self._pending[name]
        self._log(f'芯片{item["chip"]} · {item["name"]} · TX {len(item["tx_hex"]) // 2}B / RX {len(item["rx_hex"]) // 2}B · {item["elapsed_ms"]}ms · ' + ('完成' if item['ok'] else f'失败：{item["error"]}'))

    def _field(self, name, raw):
        self.raw[name] = bytes(raw)
        data = normal_order(raw)
        self.fields[name] = data
        if name in TRANSFER_ENDPOINTS:
            self._pending[name] = data
        self.emit({'type': 'field', 'name': name, 'data': data})
        self._log(f'{name}：{len(data)}B，已更新正常序HEX显示')

    def _editable_names(self):
        if self._closed or self._failed or self.result is not None:
            return ()
        return tuple(name for name in self._pending if name not in self._delivered)

    @property
    def editable_transfers(self):
        return () if self._operation_lock.locked() else self._editable_names()

    def set_transfer(self, name, data):
        """Edit a normal-order outgoing copy only while the session is idle."""
        if not self._operation_lock.acquire(blocking=False):
            raise RuntimeError('正在执行芯片命令，请等待暂停后再修改发送副本')
        try:
            if name not in self._editable_names():
                raise ValueError('该字段尚未生成、已发送或会话已结束，只能查看，不能再修改')
            if not isinstance(data, (bytes, bytearray)):
                raise ValueError('发送副本必须为字节数据')
            value = bytes(data)
            original = self.fields[name]
            if len(value) != len(original):
                raise ValueError(f'只能等长修改：原始{len(original)}字节，当前{len(value)}字节')
            before = self._pending[name]
            offsets = diff_offsets(original, value)
            self._pending[name] = value
            self.edit_history.append({'time': datetime.now(CHINA_TIME).isoformat(timespec='milliseconds'),
                                      'name': name, 'before_hex': before.hex().upper(),
                                      'after_hex': value.hex().upper(), 'changed_offsets': offsets})
            self._log(f'发送副本 {name}：与原始数据有{len(offsets)}字节差异，正常序偏移（从0开始）={offsets}；尚未发送')
            self.emit({'type': 'transfer', 'name': name, 'data': value,
                       'original': original, 'changed_offsets': offsets})
        finally:
            self._operation_lock.release()

    def reset_transfer(self, name):
        if name not in self.fields:
            raise ValueError('该字段尚未生成')
        self.set_transfer(name, self.fields[name])

    def _record_delivery(self, name, value):
        """Record the input actually submitted and acknowledged, not a read-back."""
        self._delivered[name] = bytes(value)
        self._field('received_' + name, normal_order(value))
        offsets = diff_offsets(self.fields[name], value)
        self._log(f'芯片{TRANSFER_ENDPOINTS[name][1]}输入 {name} 已下发并获得响应；差异{len(offsets)}B（不是芯片读回值）')

    def _initialize(self):
        try:
            for chip, port in ((1, self.config.port1), (2, self.config.port2)):
                if self.transport_factory:
                    transport = self.transport_factory(chip, self.config, self.profile)
                elif self.config.simulate:
                    from simulation import SimulatedTransport
                    transport = SimulatedTransport(self.profile)
                else:
                    transport = SerialTransport(port.strip(), self.config.baudrate, self.config.timeout,
                                                self.config.command_timeout, self.config.command_interval)
                self._transports.append(transport)
                transport.connect()
                client = ChipClient(transport, self.profile, chip, self._trace)
                self.clients.append(client)
                client.initialize()
                self._log(f'芯片{chip}已连接并配置：{self.profile.name}')
        except Exception:
            self._disconnect()
            raise

    def _keygen(self):
        first = self.clients[0]
        first.generate_keypair()
        self._field('pk', first.read_public_key())
        self._field('sk', first.read_private_key())

    def _transfer_pk(self):
        value = self._pending['pk']
        self.clients[1].write_public_key(normal_order(value))
        self._record_delivery('pk', value)

    def _encaps(self):
        ct, key = self.clients[1].encapsulate()
        self._field('ct', ct)
        self._field('k2', key)

    def _decaps(self):
        self._log('将当前密文发送副本转发至芯片1，私钥仅在芯片1装载；字节差异不阻止执行')
        self.clients[0].write_private_key(self.raw['sk'])
        value = self._pending['ct']
        key = self.clients[0].decapsulate(normal_order(value))
        self._record_delivery('ct', value)
        self._field('k1', key)

    def _compare(self):
        ok = secrets.compare_digest(self.fields['k1'], self.fields['k2'])
        self._finish(ok, 'K1与K2完全一致' if ok else 'K1与K2不一致，保留双方实际返回值')

    def _sign(self):
        self.fields['message'] = self.config.message
        self._pending['message'] = self.config.message
        self.emit({'type': 'field', 'name': 'message', 'data': self.config.message})
        self.clients[0].write_private_key(self.raw['sk'])
        self._field('signature', self.clients[0].sign(self.config.message))

    def _transfer_signature(self):
        self._transfer_pk()
        self._log(f'准备将{len(self.config.message)}B消息与{len(self.raw["signature"])}B签名发送至芯片2；下一步验签命令携带二者')

    def _verify(self):
        signature = self._pending['signature']
        message = self._pending['message']
        ok, response = self.clients[1].verify(normal_order(signature), message)
        self._record_delivery('signature', signature)
        self._record_delivery('message', message)
        self._field('verify_response', response)
        self._finish(ok, '芯片2验签通过（返回码00）' if ok else '芯片2验签失败（返回码01）')

    def _finish(self, ok, message):
        self.result = bool(ok)
        tampered = any(self.fields[name] != value for name, value in self._delivered.items())
        if tampered:
            message = '篡改后实际结果：' + message
        self._log(('模拟流程结果：' if self.config.simulate else '硬件结果：') + message)
        self.emit({'type': 'result', 'ok': self.result, 'message': message, 'tampered': tampered})

    def step(self):
        if not self._operation_lock.acquire(blocking=False):
            raise RuntimeError('会话正在执行，请等待当前操作完成')
        try:
            self._stopped.clear()
            self.waiting_for_transfer = None
            self._execute_next()
        finally:
            self._operation_lock.release()

    def _execute_next(self):
        if self._closed or self._failed:
            raise RuntimeError('会话已关闭或发生通信错误，请断开后重新创建会话')
        if self.next_step >= len(self.steps):
            return
        index = self.next_step
        name = self.steps[index]
        self.emit({'type': 'step', 'index': index, 'name': name, 'state': 'running'})
        self._log(f'步骤 {index + 1}/{len(self.steps)}：{name}')
        try:
            self._actions[index]()
        except Exception as exc:
            self._failed = True
            self.emit({'type': 'step', 'index': index, 'name': name, 'state': 'error'})
            self._log(f'流程中止：{exc}')
            self._disconnect()
            raise
        self.next_step += 1
        self.emit({'type': 'step', 'index': index, 'name': name, 'state': 'done'})

    def run(self):
        if not self._operation_lock.acquire(blocking=False):
            raise RuntimeError('会话正在执行，请等待当前操作完成')
        try:
            if self._closed or self._failed:
                raise RuntimeError('会话已关闭或发生通信错误，请断开后重新创建会话')
            self._stopped.clear()
            resume_at = self.waiting_for_transfer
            self.waiting_for_transfer = None
            barriers = (2, 4) if self.profile.family == 'kem' else (3,)
            while self.next_step < len(self.steps) and not self._stopped.is_set():
                if self.config.pause_before_transfer and self.next_step in barriers and self.next_step != resume_at:
                    self.waiting_for_transfer = self.next_step
                    message = f'发送前暂停：{self.steps[self.next_step]}；可篡改/对比发送副本，再继续执行'
                    self._log(message)
                    self.emit({'type': 'pause', 'index': self.next_step, 'message': message})
                    break
                self._execute_next()
                resume_at = None
            if self._stopped.is_set():
                self._log('已停止，当前步骤结束；可单步或一键继续')
        finally:
            self._operation_lock.release()

    def stop(self):
        self._stopped.set()

    def _disconnect(self):
        for transport in self._transports:
            try:
                transport.close()
            except Exception as exc:
                self._log(f'关闭串口失败：{exc}')

    def close(self):
        self._stopped.set()
        self._disconnect()
        self._closed = True

    def export(self, directory):
        destination = Path(directory) / datetime.now(CHINA_TIME).strftime('%Y%m%d_%H%M%S_%f')
        destination.mkdir(parents=True, exist_ok=False)
        config = asdict(self.config)
        config['message'] = self.config.message.hex().upper()
        transfers = {}
        for name, pending in self._pending.items():
            original = self.fields[name]
            delivered = self._delivered.get(name)
            sent = self._sent.get(name)
            transfers[name] = {'source_chip': TRANSFER_ENDPOINTS[name][0],
                               'target_chip': TRANSFER_ENDPOINTS[name][1],
                               'original_hex': original.hex().upper(), 'pending_hex': pending.hex().upper(),
                               'sent_hex': sent.hex().upper() if sent is not None else None,
                               'changed_offsets': diff_offsets(original, sent if sent is not None else pending),
                               'delivered': delivered is not None, 'read_back': False,
                               **self._send_attempts.get(name, {'send_status': 'not_sent',
                                                               'tx_command_hex': '', 'attempted_command_hex': ''})}
        comparisons = {f'{left}:{right}': diff_offsets(self.fields[left], self.fields[right])
                       for left, right in COMPARISON_PAIRS if left in self.fields and right in self.fields}
        result = {'started_at': self.started_at, 'mode': 'simulation' if self.config.simulate else 'hardware',
                  'simulation_notice': 'Protocol preview only; not a PQC implementation' if self.config.simulate else '',
                  'config': config, 'result': self.result, 'completed_steps': self.next_step,
                  'total_steps': len(self.steps), 'communication_error': self._failed,
                  'byte_order': 'normal/software order; each complete wire field reversed',
                  'fields_hex': {key: value.hex().upper() for key, value in self.fields.items()},
                  'transfers': transfers, 'comparisons': comparisons, 'edit_history': self.edit_history,
                  'waiting_for_transfer': self.waiting_for_transfer,
                  'tampered': any(self.fields[name] != value for name, value in self._sent.items())}
        (destination / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        (destination / 'command_trace.json').write_text(json.dumps(self.trace, ensure_ascii=False, indent=2), encoding='utf-8')
        (destination / 'session.log').write_text('\n'.join(self.logs) + '\n', encoding='utf-8')
        fields = ['流程模拟 / 非密码算法验证' if self.config.simulate else '真实双芯片硬件记录',
                  '字段均为正常字节序HEX；原始串口数据见command_trace.json。',
                  f'算法：{self.profile.name}', f'结果：{self.result}（None表示未取得最终结果）']
        for key, value in self.fields.items():
            fields.extend(['', f'[{key}] {len(value)} bytes', value.hex().upper()])
        fields.extend(['', '接收/输入字段表示上位机实际下发且已获有效响应的数据，不是芯片读回值。',
                       '已发送不等于已获响应；完整/部分/未知发送状态见send_status及原始TX命令。',
                       '字节偏移从0开始，按正常字节序计数。'])
        for name, transfer in transfers.items():
            fields.extend(['', f'[transfer:{name}] send_status={transfer["send_status"]} delivered={transfer["delivered"]} diff_offsets={transfer["changed_offsets"]}',
                           'ORIGINAL=' + transfer['original_hex'], 'PENDING=' + transfer['pending_hex'],
                           'SENT=' + (transfer['sent_hex'] or transfer['send_status'].upper())])
        (destination / 'fields.txt').write_text('\n'.join(fields) + '\n', encoding='utf-8')
        self._log(f'记录已导出：{destination}')
        return destination
