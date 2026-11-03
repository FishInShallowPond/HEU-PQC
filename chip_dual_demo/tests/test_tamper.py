"""Fault injection must alter actual command bytes, never the original output."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from profiles import PROFILES
from protocol import ProtocolError, frame
from simulation import SimulatedTransport
from workflow import DemoConfig, DemoSession


class TamperTests(unittest.TestCase):
    def setUp(self):
        redirect = contextlib.redirect_stdout(io.StringIO())
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def make_session(self, algorithm='kyber512', pause=False):
        session = DemoSession(DemoConfig(algorithm=algorithm, simulate=True,
                                         pause_before_transfer=pause))
        self.addCleanup(session.close)
        return session

    def advance(self, session, index):
        while session.next_step < index:
            session.step()

    def test_all_algorithms_send_mutated_ciphertext_or_signature_and_finish(self):
        for algorithm, profile in PROFILES.items():
            with self.subTest(algorithm=algorithm):
                session = self.make_session(algorithm)
                name = 'ct' if profile.family == 'kem' else 'signature'
                self.advance(session, 4 if name == 'ct' else 3)
                original = session.fields[name]
                modified = bytes([original[0] ^ 1]) + original[1:]
                session.set_transfer(name, modified)
                self.assertEqual(session.fields[name], original)
                session.run()
                self.assertFalse(session.result)
                self.assertFalse(session._failed)
                self.assertEqual(session.next_step, len(session.steps))
                self.assertEqual(session.fields['received_' + name], modified)
                self.assertEqual(session.raw[name], original[::-1])
                self.assertEqual(session.fields['received_pk'], session.fields['pk'])
                opcode = '0209' if name == 'ct' else '020A'
                sent = bytes.fromhex(next(t['tx_hex'] for t in session.trace if t['tx_hex'].startswith(opcode)))
                if name == 'ct':
                    self.assertEqual(sent[5:], modified[::-1])
                    self.assertNotEqual(session.fields['k1'], session.fields['k2'])
                else:
                    self.assertEqual(sent[7:7 + len(modified)], modified[::-1])
                    self.assertEqual(session.fields['verify_response'], b'\x01')

    def test_transfers_pause_before_sending_and_resume_once(self):
        session = self.make_session(pause=True)
        events = []
        session.emit = events.append
        session.run()
        self.assertEqual(session.next_step, 2)
        self.assertEqual(session.waiting_for_transfer, 2)
        self.assertNotIn('received_pk', session.fields)
        session.run()
        self.assertEqual(session.next_step, 4)
        self.assertEqual(session.waiting_for_transfer, 4)
        self.assertIn('received_pk', session.fields)
        self.assertNotIn('received_ct', session.fields)
        session.run()
        self.assertTrue(session.result)
        self.assertEqual(len([e for e in events if e['type'] == 'pause']), 2)

    def test_signature_pause_and_tampered_message_continues_to_false_result(self):
        session = self.make_session('dilithium5', pause=True)
        session.run()
        self.assertEqual(session.next_step, 3)
        original = session.fields['message']
        changed = b'X' + original[1:]
        session.set_transfer('message', changed)
        session.run()
        self.assertFalse(session.result)
        self.assertEqual(session.fields['message'], original)
        self.assertEqual(session.fields['received_message'], changed)
        self.assertEqual(session.fields['received_signature'], session.fields['signature'])

    def test_public_key_input_is_recorded_even_if_mutated(self):
        session = self.make_session()
        self.advance(session, 2)
        original = session.fields['pk']
        changed = original[:-1] + bytes([original[-1] ^ 0x80])
        session.set_transfer('pk', changed)
        session.run()
        self.assertEqual(session.fields['pk'], original)
        self.assertEqual(session.fields['received_pk'], changed)
        self.assertFalse(session.result)

    def test_reset_restores_original_and_invalid_edits_do_not_modify_pending(self):
        session = self.make_session()
        with self.assertRaises(ValueError): session.set_transfer('ct', b'1')
        self.advance(session, 4)
        original = session.fields['ct']
        with self.assertRaises(ValueError): session.set_transfer('ct', original[:-1])
        self.assertEqual(session.pending_transfers['ct'], original)
        session.set_transfer('ct', bytes([original[0] ^ 1]) + original[1:])
        session.reset_transfer('ct')
        session.run()
        self.assertTrue(session.result)
        self.assertEqual(session.fields['received_ct'], original)
        with self.assertRaises(ValueError): session.set_transfer('ct', original)

    def test_edit_cannot_race_active_command(self):
        session = self.make_session()
        self.advance(session, 4)
        seen = []
        def emit(event):
            if event['type'] == 'step' and event['state'] == 'running':
                with self.assertRaises(RuntimeError):
                    session.set_transfer('ct', session.fields['ct'])
                seen.append(True)
        session.emit = emit
        session.run()
        self.assertTrue(seen)

    def test_export_retains_original_pending_received_and_byte_offsets(self):
        session = self.make_session()
        self.advance(session, 4)
        original = session.fields['ct']
        changed = bytearray(original)
        changed[0] ^= 1
        changed[-1] ^= 2
        session.set_transfer('ct', bytes(changed))
        session.run()
        with tempfile.TemporaryDirectory() as directory:
            path = session.export(directory)
            result = json.loads((path / 'result.json').read_text(encoding='utf-8'))
            transfer = result['transfers']['ct']
            self.assertEqual(transfer['original_hex'], original.hex().upper())
            self.assertEqual(transfer['sent_hex'], bytes(changed).hex().upper())
            self.assertEqual(transfer['changed_offsets'], [0, len(original) - 1])
            self.assertTrue(transfer['delivered'])
            self.assertFalse(transfer['read_back'])
            self.assertFalse(result['result'])
            self.assertTrue(result['edit_history'])

    def test_sent_input_is_retained_when_response_times_out_or_has_unknown_status(self):
        for algorithm in ('kyber512', 'dilithium2'):
            with self.subTest(algorithm=algorithm):
                def factory(chip, config, profile):
                    transport = SimulatedTransport(profile)
                    exchange = transport.exchange
                    transport.last_tx = b''
                    def faulty(command, **kwargs):
                        transport.last_tx = bytes(command)
                        if command[1] == 9:
                            transport.last_rx = b''
                            raise TimeoutError('after complete TX')
                        if command[1] == 10:
                            return frame(0x82, 10, b'\x02')
                        return exchange(command, **kwargs)
                    transport.exchange = faulty
                    return transport
                session = DemoSession(DemoConfig(algorithm=algorithm, simulate=True), transport_factory=factory)
                self.addCleanup(session.close)
                name = 'ct' if algorithm == 'kyber512' else 'signature'
                self.advance(session, 4 if name == 'ct' else 3)
                original = session.fields[name]
                changed = bytes([original[0] ^ 1]) + original[1:]
                session.set_transfer(name, changed)
                with self.assertRaises((TimeoutError, ProtocolError)): session.run()
                self.assertNotIn('received_' + name, session.fields)
                with tempfile.TemporaryDirectory() as directory:
                    path = session.export(directory)
                    result = json.loads((path / 'result.json').read_text(encoding='utf-8'))
                    transfer = result['transfers'][name]
                    self.assertEqual(transfer['sent_hex'], changed.hex().upper())
                    self.assertEqual(transfer['send_status'], 'complete')
                    self.assertFalse(transfer['delivered'])
                    self.assertIn('已发送', (path / 'fields.txt').read_text(encoding='utf-8'))

    def test_incomplete_or_unknown_send_is_distinct_from_not_sent(self):
        for status in ('partial', 'unknown', 'not_sent'):
            with self.subTest(status=status):
                def factory(chip, config, profile):
                    transport = SimulatedTransport(profile)
                    transport.last_tx = b''
                    transport.write_started = False
                    exchange = transport.exchange
                    def faulty(command, **kwargs):
                        transport.last_tx = bytes(command)
                        transport.write_started = True
                        if command[1] == 9:
                            transport.last_tx = command[:20] if status == 'partial' else b''
                            transport.write_started = status != 'not_sent'
                            transport.last_rx = b''
                            raise ProtocolError('injected send failure')
                        return exchange(command, **kwargs)
                    transport.exchange = faulty
                    return transport
                session = DemoSession(DemoConfig(simulate=True), transport_factory=factory)
                self.addCleanup(session.close)
                self.advance(session, 4)
                with self.assertRaises(ProtocolError): session.run()
                with tempfile.TemporaryDirectory() as directory:
                    path = session.export(directory)
                    result = json.loads((path / 'result.json').read_text(encoding='utf-8'))
                    transfer = result['transfers']['ct']
                    self.assertEqual(transfer['send_status'], status)
                    self.assertIsNone(transfer['sent_hex'])
                    self.assertFalse(transfer['delivered'])
                    self.assertEqual(len(transfer['tx_command_hex']) // 2, 20 if status == 'partial' else 0)
                    self.assertEqual(len(transfer['attempted_command_hex']) // 2, 773)


if __name__ == '__main__':
    unittest.main()
