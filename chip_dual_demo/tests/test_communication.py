"""One-click chip-1 signature verification, fresh KEM and text AEAD."""
import contextlib
import io
import json
import tempfile
import threading
import unittest

from communication import CommunicationConfig, CommunicationSession
from profiles import PROFILES
from protocol import ProtocolError, frame
from simulation import SimulatedTransport


class CommunicationTests(unittest.TestCase):
    def setUp(self):
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        self.config = CommunicationConfig(simulate=True)
        self.transports = []

    def factory(self, chip, config, profile):
        transport = SimulatedTransport(profile)
        transport.chip = chip
        transport.commands = []
        original = transport.exchange
        def exchange(command, **kwargs):
            transport.commands.append(bytes(command))
            return original(command, **kwargs)
        transport.exchange = exchange
        self.transports.append(transport)
        return transport

    def session(self, factory=None, config=None):
        session = CommunicationSession(config or self.config, transport_factory=factory or self.factory)
        self.addCleanup(session.close)
        return session

    def test_chip1_signs_and_chip2_verifies_before_kem_without_identity_file(self):
        session = self.session()
        session.connect()
        epoch = session.epochs[0]
        self.assertTrue(session.ready)
        self.assertEqual([(proof['phase'], proof['signer'], proof['verifier']) for proof in epoch['proofs']],
                         [('session_signing', 'A', 'B'), ('key_binding', 'A', 'B')])
        self.assertTrue(all(proof['verified'] for proof in epoch['proofs']))
        self.assertTrue(all(len(bytes.fromhex(proof['message_hex'])) == 33 for proof in epoch['proofs']))
        self.assertTrue(epoch['session_signing_verified'])
        self.assertEqual(epoch['signing_scope'], 'current_session_only')
        self.assertFalse(epoch['stored_signing_credentials'])
        self.assertFalse(epoch['direct_k_comparison'])
        self.assertEqual(session.send('A', '你好B')['received_text'], '你好B')
        self.assertEqual(session.send('B', '收到A🙂')['received_text'], '收到A🙂')
        commands = [command for transport in self.transports for command in transport.commands]
        self.assertTrue(any(command[:2] == b'\x02\x08' for command in commands))
        self.assertTrue(any(command[:2] == b'\x02\x09' for command in commands))
        self.assertTrue(any(command[:2] == b'\x02\x0a' for command in commands))

    def test_each_new_session_gets_a_fresh_ephemeral_chip1_signature_key(self):
        first = self.session(); first.connect()
        first_fingerprint = first.epochs[0]['public_data']['session_signing_public_key_fingerprint']
        first.close()
        self.transports.clear()
        second = self.session(); second.connect()
        second_fingerprint = second.epochs[0]['public_data']['session_signing_public_key_fingerprint']
        self.assertNotEqual(first_fingerprint, second_fingerprint)
        self.assertFalse(second.epochs[0]['stored_signing_credentials'])

    def test_rekey_repeats_chip1_signature_and_creates_fresh_kem_outputs(self):
        session = self.session(); session.connect()
        session.send('A', '旧轮对话')
        old = session.exchange
        public = dict(session.epochs[0]['public_data'])
        fingerprint = session.epochs[0]['public_data']['session_signing_public_key_fingerprint']
        counts = sum(command[:2] == b'\x02\x01' for transport in self.transports for command in transport.commands)
        session.rekey()
        self.assertFalse(old.ready)
        self.assertTrue(session.ready)
        self.assertNotEqual(old.session_id, session.exchange.session_id)
        self.assertNotEqual(public['kem_pk_hex'], session.epochs[1]['public_data']['kem_pk_hex'])
        self.assertNotEqual(public['kem_ct_hex'], session.epochs[1]['public_data']['kem_ct_hex'])
        self.assertNotEqual(
            session.epochs[1]['public_data']['session_signing_public_key_fingerprint'], fingerprint)
        # One fresh chip-1 signature key and one fresh KEM key per handshake.
        self.assertEqual(sum(command[:2] == b'\x02\x01' for transport in self.transports for command in transport.commands), counts + 2)
        self.assertEqual(session.send('B', '新轮对话')['sequence'], 0)
        snapshots = session.snapshot()['text_sessions']
        self.assertEqual([item['records'][0]['received_text'] for item in snapshots], ['旧轮对话', '新轮对话'])

    def test_valid_signature_rejection_blocks_kem_and_conversation(self):
        def rejecting(chip, config, profile):
            transport = self.factory(chip, config, profile)
            original = transport.exchange
            def exchange(command, **kwargs):
                answer = original(command, **kwargs)
                return frame(0x82, 10, b'\x01') if command[:2] == b'\x02\x0a' else answer
            transport.exchange = exchange
            return transport
        session = self.session(rejecting)
        with self.assertRaises(RuntimeError): session.connect()
        self.assertFalse(session.ready)
        self.assertFalse(session.epochs[0]['session_signing_verified'])
        self.assertFalse(any(command[:2] == b'\x02\x08' for transport in self.transports for command in transport.commands))
        with self.assertRaises(RuntimeError): session.send('A', 'blocked')

    def test_unknown_verify_response_is_communication_error(self):
        def failing(chip, config, profile):
            transport = self.factory(chip, config, profile)
            original = transport.exchange
            def exchange(command, **kwargs):
                answer = original(command, **kwargs)
                return frame(0x82, 10, b'\x02') if command[:2] == b'\x02\x0a' else answer
            transport.exchange = exchange
            return transport
        session = self.session(failing)
        with self.assertRaises(RuntimeError): session.connect()
        self.assertEqual(session.snapshot()['terminal_error']['code'], 'communication_error')
        self.assertTrue(all(transport.closed for transport in self.transports))

    def test_signed_kem_binding_rejection_never_publishes_text_keys(self):
        verified = []
        def failing(chip, config, profile):
            transport = self.factory(chip, config, profile)
            original = transport.exchange
            def exchange(command, **kwargs):
                answer = original(command, **kwargs)
                if command[:2] == b'\x02\x0a':
                    verified.append(command)
                    if len(verified) == 2: return frame(0x82, 10, b'\x01')
                return answer
            transport.exchange = exchange
            return transport
        session = self.session(failing)
        with self.assertRaises(RuntimeError): session.connect()
        self.assertFalse(session.ready)
        self.assertEqual(session.snapshot()['terminal_error']['code'], 'key_binding_failed')
        self.assertFalse(session.snapshot()['text_sessions'])

    def test_wrong_chip_k_is_not_copied_or_compared(self):
        def failing(chip, config, profile):
            transport = self.factory(chip, config, profile)
            original = transport.exchange
            def exchange(command, **kwargs):
                answer = original(command, **kwargs)
                return frame(0x82, 9, b'x' * 32) if command[:2] == b'\x02\x09' else answer
            transport.exchange = exchange
            return transport
        session = self.session(failing)
        with self.assertRaises(RuntimeError): session.connect()
        self.assertFalse(session.ready)
        self.assertEqual(session.snapshot()['terminal_error']['code'], 'key_confirmation_failed')

    def test_rekey_failure_closes_old_keys_without_silent_fallback(self):
        session = self.session(); session.connect()
        old = session.exchange
        original = self.transports[0].exchange
        def fail(command, **kwargs):
            if command[:2] == b'\x02\x0b': raise TimeoutError('injected timeout')
            return original(command, **kwargs)
        self.transports[0].exchange = fail
        with self.assertRaises(RuntimeError): session.rekey()
        self.assertFalse(old.ready)
        self.assertFalse(session.ready)
        with self.assertRaises(RuntimeError): session.send('A', 'blocked')

    def test_export_preserves_public_signatures_and_redacts_secret_commands(self):
        session = self.session(); session.connect(); session.send('A', 'export me')
        session.rekey(); session.send('B', 'reject me', fault='tag')
        with tempfile.TemporaryDirectory() as directory:
            path = session.export(directory)
            data = json.loads((path / 'communication.json').read_text(encoding='utf-8'))
            self.assertEqual(len(data['epochs']), 2)
            self.assertTrue(all(item['session_signing_verified'] for item in data['epochs']))
            self.assertTrue(all(item['stored_signing_credentials'] is False for item in data['epochs']))
            self.assertTrue(all(item['public_data']['session_signing_public_key_hex'] for item in data['epochs']))
            self.assertIsNone(data['text_sessions'][1]['records'][0]['received_text'])
            traces = json.loads((path / 'command_trace.json').read_text(encoding='utf-8'))
            self.assertTrue(any(trace.get('tx_redacted') or trace.get('rx_redacted') for trace in traces))
            self.assertTrue(all('tx_bytes' in trace and 'rx_bytes' in trace for trace in traces))
            rendered = json.dumps(data)
            for forbidden in ('private_a', 'private_b', 'k1_hex', 'k2_hex', 'signature_private'):
                self.assertNotIn(forbidden, rendered)

    def test_close_during_handshake_cannot_leave_ready_exchange(self):
        started, resume = threading.Event(), threading.Event()
        def paused(chip, config, profile):
            transport = self.factory(chip, config, profile)
            original = transport.exchange
            def exchange(command, **kwargs):
                if command[:2] == b'\x02\x08':
                    started.set()
                    if not resume.wait(5): raise TimeoutError('test gate')
                return original(command, **kwargs)
            transport.exchange = exchange
            return transport
        session = self.session(paused)
        errors = []
        def connecting():
            try: session.connect()
            except RuntimeError as exc: errors.append(exc)
        worker = threading.Thread(target=connecting); worker.start()
        closer = threading.Thread(target=session.close)
        try:
            self.assertTrue(started.wait(5)); closer.start()
            self.assertTrue(session._stop_event.wait(5))
        finally:
            resume.set(); worker.join(5)
            if closer.ident is not None: closer.join(5)
        self.assertFalse(worker.is_alive() or closer.is_alive())
        self.assertFalse(session.ready)
        self.assertTrue(session.closed)
        self.assertTrue(all(transport.closed for transport in self.transports))

    def test_secret_command_failure_never_exports_private_or_shared_key_text(self):
        canary = 'SECRET-CANARY-K' + 'AA' * 32
        def failing(chip, config, profile):
            transport = self.factory(chip, config, profile)
            original = transport.exchange
            def exchange(command, **kwargs):
                if command[:2] == b'\x02\x09': raise ProtocolError(canary)
                return original(command, **kwargs)
            transport.exchange = exchange
            return transport
        session = self.session(failing)
        with self.assertRaises(RuntimeError): session.connect()
        rendered = json.dumps(session.snapshot(), ensure_ascii=False)
        self.assertNotIn(canary, rendered)
        with tempfile.TemporaryDirectory() as directory:
            path = session.export(directory)
            combined = ''.join(item.read_text(encoding='utf-8') for item in path.iterdir())
            self.assertNotIn(canary, combined)

    def test_close_archives_current_chat_for_post_disconnect_export(self):
        session = self.session(); session.connect(); session.send('A', '关闭后仍应保留')
        session.close()
        snapshot = session.snapshot()
        self.assertTrue(snapshot['closed'])
        self.assertEqual(snapshot['text_sessions'][-1]['records'][0]['received_text'], '关闭后仍应保留')
        with tempfile.TemporaryDirectory() as directory:
            data = json.loads((session.export(directory) / 'communication.json').read_text(encoding='utf-8'))
            self.assertEqual(data['text_sessions'][-1]['records'][0]['received_text'], '关闭后仍应保留')

    def test_every_signature_and_kem_profile_works_through_one_click_handshake(self):
        signatures = [key for key, profile in PROFILES.items() if profile.family == 'signature']
        kems = [key for key, profile in PROFILES.items() if profile.family == 'kem']
        cases = [(key, 'kyber512') for key in signatures] + [('dilithium2', key) for key in kems]
        for signature, kem in cases:
            with self.subTest(signature=signature, kem=kem):
                self.transports.clear()
                config = CommunicationConfig(signature, kem, simulate=True)
                session = CommunicationSession(config, transport_factory=self.factory)
                try:
                    session.connect()
                    self.assertTrue(session.ready)
                    self.assertTrue(session.send('A', '配置互通')['ok'])
                    commands = [command for transport in self.transports for command in transport.commands]
                    self.assertIn(bytes.fromhex(PROFILES[signature].config_hex), commands)
                    self.assertIn(bytes.fromhex(PROFILES[kem].config_hex), commands)
                finally:
                    session.close()

    def test_invalid_communication_configuration_is_rejected_before_ports(self):
        for config in (
                CommunicationConfig('kyber512', 'kyber512', simulate=True),
                CommunicationConfig('dilithium2', 'dilithium2', simulate=True),
                CommunicationConfig(port1='COM5', port2='com5')):
            with self.subTest(config=config), self.assertRaises(ValueError):
                CommunicationSession(config, transport_factory=self.factory)
        self.assertFalse(self.transports)

    def test_records_file_in_both_directions_and_exposes_local_key_inspector(self):
        session = self.session(); session.connect()
        data = b'\x89PNG\r\n\x1a\nchat image bytes' * 5000
        from_a = session.send_file('A', 'a.png', 'image/png', data)
        from_b = session.send_file('B', 'b.png', 'image/png', data)
        self.assertTrue(from_a['ok'] and from_b['ok'])
        self.assertEqual(session.payload(from_a['payload_id']), data)
        self.assertEqual(session.payload(from_b['payload_id']), data)
        keys = session.key_material()
        self.assertEqual(len(bytes.fromhex(keys['k_a_hex'])), 32)
        self.assertEqual(len(bytes.fromhex(keys['a_to_b_aes_hex'])), 32)
        exported = json.dumps(session.snapshot())
        self.assertNotIn(keys['k_a_hex'], exported)
        self.assertNotIn(keys['a_to_b_aes_hex'], exported)
        self.assertEqual([record['kind'] for record in session.snapshot()['text_sessions'][-1]['records']],
                         ['file', 'file'])
