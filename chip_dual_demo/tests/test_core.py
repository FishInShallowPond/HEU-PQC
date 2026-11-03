"""Protocol and two-chip integration tests: no physical serial ports required."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from profiles import PROFILES
from protocol import ChipClient, ProtocolError, SerialTransport, frame, normal_order, prepare_message
from simulation import SimulatedTransport
from workflow import DemoConfig, DemoSession


class QuietTest(unittest.TestCase):
    def setUp(self):
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)


class TwoChipTests(QuietTest):
    def session(self, algorithm='kyber512'):
        return DemoSession(DemoConfig(algorithm=algorithm, simulate=True), emit=lambda e: None)

    def test_all_algorithms_complete_and_transfer_exact_bytes(self):
        for key, profile in PROFILES.items():
            with self.subTest(key=key):
                session = self.session(key)
                session.run()
                self.assertTrue(session.result)
                self.assertEqual(session.next_step, len(session.steps))
                public_write = next(t for t in session.trace if t['chip'] == 2 and t['tx_hex'].startswith('0204'))
                self.assertEqual(bytes.fromhex(public_write['tx_hex'])[5:], session.fields['pk'][::-1])
                self.assertFalse(any(t['chip'] == 2 and t['tx_hex'].startswith('0205') for t in session.trace))
                if profile.family == 'kem':
                    self.assertEqual(session.fields['k1'], session.fields['k2'])
                    self.assertEqual(len(session.fields['pk']), 800)
                    self.assertEqual(len(session.fields['ct']), 768)
                    decaps = next(t for t in session.trace if t['tx_hex'].startswith('0209'))
                    self.assertEqual(bytes.fromhex(decaps['tx_hex'])[5:], session.fields['ct'][::-1])
                else:
                    self.assertEqual(session.fields['message'], session.config.message)
                    sign = next(t for t in session.trace if t['tx_hex'].startswith('020B'))
                    verify = next(t for t in session.trace if t['tx_hex'].startswith('020A'))
                    self.assertEqual(bytes.fromhex(sign['tx_hex'])[5:], prepare_message(session.config.message))
                    self.assertTrue(bytes.fromhex(verify['tx_hex']).endswith(prepare_message(session.config.message)))
                session.close()

    def test_k_mismatch_is_not_rewritten(self):
        session = self.session()
        while session.next_step < len(session.steps) - 1:
            session.step()
        session.fields['k1'] = b'\xFF' * 32
        session.step()
        self.assertFalse(session.result)
        self.assertNotEqual(session.fields['k1'], session.fields['k2'])
        session.close()

    def test_verify_rejection_is_not_rewritten(self):
        session = self.session('dilithium2')
        while session.next_step < len(session.steps) - 1:
            session.step()
        original = session.fields['signature']
        session.set_transfer('signature', bytes([original[0] ^ 1]) + original[1:])
        session.step()
        self.assertFalse(session.result)
        self.assertEqual(session.fields['verify_response'], b'\x01')
        session.close()

    def test_stop_leaves_next_step_resumable(self):
        session = self.session()
        def stop_after_initialization(event):
            if event['type'] == 'step' and event['index'] == 0 and event['state'] == 'done':
                session.stop()
        session.emit = stop_after_initialization
        session.run()
        self.assertEqual(session.next_step, 1)
        self.assertIsNone(session.result)
        session.emit = lambda event: None
        session.run()
        self.assertTrue(session.result)
        session.close()

    def test_export_contains_full_fields_and_raw_traces(self):
        session = self.session()
        session.run()
        with tempfile.TemporaryDirectory() as directory:
            path = session.export(directory)
            result = json.loads((path / 'result.json').read_text(encoding='utf-8'))
            self.assertTrue(result['result'])
            self.assertEqual(result['fields_hex']['pk'], session.fields['pk'].hex().upper())
            self.assertTrue((path / 'command_trace.json').is_file())
            self.assertIn('模拟', (path / 'session.log').read_text(encoding='utf-8'))
        session.close()

    def test_same_port_and_invalid_signature_message_rejected_before_connect(self):
        with self.assertRaises(ValueError):
            DemoSession(DemoConfig(port1='com5', port2=' COM5 '))
        for message in (b'', b'12345678', b'a' * 1001):
            with self.subTest(message_length=len(message)), self.assertRaises(ValueError):
                DemoSession(DemoConfig(algorithm='dilithium2', message=message, simulate=True))


class ProtocolTests(QuietTest):
    def test_normal_order_is_whole_field_reverse(self):
        self.assertEqual(normal_order(bytes.fromhex('01020304AABB')), bytes.fromhex('BBAA04030201'))
        self.assertEqual(prepare_message(b'abc'), b'\x00' * 5 + b'cba' + b'\x00' * 2)

    def test_wrong_header_truncation_and_extra_decaps_data_rejected(self):
        class BadTransport:
            def __init__(self, response): self.response = response
            def exchange(self, command, **kwargs): return self.response
            def close(self): pass
        for response in (b'\x82', frame(0x81, 9, b'x' * 32), frame(0x82, 9, b'x' * 31), frame(0x82, 9, b'x' * 33)):
            with self.subTest(response=response), self.assertRaises(ProtocolError):
                ChipClient(BadTransport(response), PROFILES['kyber512'], 1).decapsulate(b'a' * 768)

    def test_short_public_key_is_rejected_without_padding(self):
        class ShortTransport:
            def exchange(self, command, **kwargs): return frame(0x82, 2, b'a' * 799)
        with self.assertRaises(ProtocolError):
            ChipClient(ShortTransport(), PROFILES['kyber1024'], 1).read_public_key()

    def test_unknown_verify_status_is_recorded_as_protocol_error(self):
        class UnknownTransport:
            def exchange(self, command, **kwargs): return frame(0x82, 10, b'\x02')
        trace = []
        client = ChipClient(UnknownTransport(), PROFILES['dilithium2'], 2, trace.append)
        with self.assertRaises(ProtocolError): client.verify(b'a' * 2420, b'abc')
        self.assertFalse(trace[0]['ok'])

    def test_enable_alarm_stops_before_configuration(self):
        class AlarmTransport:
            def __init__(self): self.commands = []
            def exchange(self, command, **kwargs):
                self.commands.append(command)
                return b'' if command[1] == 6 else bytes.fromhex('810301000001')
        transport = AlarmTransport()
        trace = []
        client = ChipClient(transport, PROFILES['kyber512'], 1, trace.append)
        with self.assertRaises(ProtocolError): client.initialize()
        self.assertEqual(len(transport.commands), 2)
        self.assertFalse(trace[-1]['ok'])

    def test_failing_initialization_closes_both_transports(self):
        transports = []
        def factory(chip, config, profile):
            t = SimulatedTransport(profile)
            transports.append(t)
            if chip == 2:
                def fail(*args, **kwargs): raise OSError('injected disconnect')
                t.exchange = fail
            return t
        session = DemoSession(DemoConfig(simulate=True), transport_factory=factory)
        with self.assertRaises(OSError): session.step()
        self.assertTrue(all(t.closed for t in transports))
        self.assertIsNone(session.result)
        with self.assertRaises(RuntimeError): session.step()


class SerialTests(QuietTest):
    class Port:
        is_open = True
        timeout = 0.2
        out_waiting = 0
        def __init__(self, response, chunk=1):
            self.response = bytearray()
            self.answer = response
            self.chunk = chunk
            self.read_count = 0
            self.writes = []
        def reset_input_buffer(self): pass
        def write(self, data):
            self.writes.append(data)
            self.response.extend(self.answer)
            return len(data)
        @property
        def in_waiting(self): return len(self.response)
        def flush(self): pass
        def read(self, size):
            self.read_count += 1
            data = bytes(self.response[:min(size, self.chunk)])
            del self.response[:len(data)]
            return data
        def close(self): self.is_open = False

    def transport(self, response, chunk=1):
        transport = SerialTransport('TEST', command_timeout=0.015, command_interval=0)
        transport.serial = self.Port(response, chunk)
        return transport

    def test_fragmented_response_and_zero_length_ack(self):
        for response in (frame(0x82, 2, bytes(range(100))), frame(0x82, 0)):
            with self.subTest(length=len(response)):
                transport = self.transport(response)
                self.assertEqual(transport.exchange(frame(2, 2)), response)
                self.assertEqual(transport.last_rx, response)

    def test_truncated_payload_times_out_and_retains_partial_rx(self):
        response = frame(0x82, 2, b'123456')[:-1]
        transport = self.transport(response)
        with self.assertRaises(TimeoutError): transport.exchange(frame(2, 2))
        self.assertEqual(transport.last_rx, response)

    def test_oversized_length_rejected_before_payload_read(self):
        response = bytes.fromhex('8202FFFFFF')
        transport = self.transport(response, 5)
        with self.assertRaises(ProtocolError): transport.exchange(frame(2, 2))
        self.assertEqual(transport.serial.read_count, 1)

    def test_partial_serial_write_is_failure(self):
        transport = self.transport(b'')
        transport.serial.write = lambda data: len(data) - 1
        with self.assertRaises(ProtocolError): transport.exchange(frame(2, 2))

    def test_stalled_send_queue_obeys_command_deadline(self):
        transport = self.transport(frame(0x82, 2))
        transport.serial.out_waiting = 1
        with self.assertRaises(TimeoutError): transport.exchange(frame(2, 2))

    def test_trailing_alarm_is_preserved_and_rejected(self):
        response = frame(0x82, 4, b'\x00') + frame(0x81, 4, b'\x01')
        transport = self.transport(response, 100)
        with self.assertRaises(ProtocolError): transport.exchange(frame(2, 4, b'a' * 800))
        self.assertEqual(transport.last_rx, response)

    def test_residual_input_is_preserved_before_sending(self):
        transport = self.transport(b'')
        alarm = frame(0x81, 4, b'\x01')
        transport.serial.response.extend(alarm)
        with self.assertRaises(ProtocolError): transport.exchange(frame(2, 4, b'a' * 800))
        self.assertEqual(transport.last_rx, alarm)
        self.assertEqual(transport.serial.writes, [])

    def test_bad_ack_and_chip_alarm_retained_in_failed_trace(self):
        class BadTransport:
            def __init__(self, response): self.response = response
            def exchange(self, command, **kwargs): return self.response
        for response in (frame(0x82, 4, b'\x01'), frame(0x81, 4, b'\x01')):
            trace = []
            client = ChipClient(BadTransport(response), PROFILES['kyber512'], 2, trace.append)
            with self.assertRaises(ProtocolError): client.write_public_key(b'a' * 800)
            self.assertFalse(trace[0]['ok'])
            self.assertEqual(trace[0]['rx_hex'], response.hex().upper())

    def test_both_workflows_through_serial_transport_with_fragmented_emulated_ports(self):
        # Exercise the actual byte transport with two independent emulated UARTs,
        # rather than bypassing SerialTransport with the protocol simulator.
        for algorithm in ('kyber1024', 'dilithium5'):
            with self.subTest(algorithm=algorithm):
                ports = []
                class EmulatedPort(self.Port):
                    def __init__(self, profile):
                        super().__init__(b'', chunk=13)
                        self.peer = SimulatedTransport(profile)
                    def write(self, data):
                        self.writes.append(data)
                        self.response.extend(self.peer.exchange(data))
                        return len(data)
                def factory(chip, config, profile):
                    transport = SerialTransport(f'EMU{chip}', command_interval=0)
                    port = EmulatedPort(profile)
                    ports.append(port)
                    transport.connect = lambda: setattr(transport, 'serial', port)
                    return transport
                session = DemoSession(DemoConfig(algorithm=algorithm), transport_factory=factory)
                session.run()
                self.assertTrue(session.result)
                self.assertEqual(len(ports), 2)
                self.assertTrue(all(t['tx_hex'] == t['attempted_tx_hex'] for t in session.trace))
                session.close()
                self.assertTrue(all(not p.is_open for p in ports))


if __name__ == '__main__':
    unittest.main()
