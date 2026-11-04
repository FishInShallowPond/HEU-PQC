import contextlib
import io
import json
import tempfile
import threading
import unittest
from unittest.mock import patch

from workflow import DemoConfig, DemoSession


class TextWorkflowTests(unittest.TestCase):
    def setUp(self):
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def session(self, algorithm='kyber512'):
        session = DemoSession(DemoConfig(algorithm=algorithm, simulate=True))
        self.addCleanup(session.close)
        return session

    def test_incomplete_signature_and_closed_sessions_cannot_create_text_keys(self):
        session = self.session()
        with self.assertRaises(RuntimeError): session.open_text_exchange()
        session.run()
        session.close()
        with self.assertRaises(RuntimeError): session.open_text_exchange()
        signature = self.session('dilithium2')
        signature.run()
        with self.assertRaises(RuntimeError): signature.open_text_exchange()

    def test_each_algorithm_uses_actual_kem_outputs_and_preserves_uart_trace(self):
        for algorithm in ('kyber512', 'aigis-enc2'):
            session = self.session(algorithm)
            session.run()
            before = len(session.trace)
            channel = session.open_text_exchange()
            self.assertIs(session.open_text_exchange(), channel)
            self.assertTrue(channel.ready)
            self.assertEqual(channel.send('A', '来自芯片1的密钥')['received_text'], '来自芯片1的密钥')
            self.assertEqual(channel.send('B', '来自芯片2的密钥')['received_text'], '来自芯片2的密钥')
            self.assertEqual(len(session.trace), before, '业务文本不经过控制串口')

    def test_tampered_pk_or_ct_fails_confirmation_without_rewriting_k(self):
        for name, index in (('pk', 2), ('ct', 4)):
            session = self.session()
            while session.next_step < index: session.step()
            original = session.fields[name]
            session.set_transfer(name, bytes([original[0] ^ 1]) + original[1:])
            session.run()
            keys = (session.fields['k1'], session.fields['k2'])
            channel = session.open_text_exchange()
            self.assertFalse(channel.ready)
            self.assertNotEqual(keys[0], keys[1])
            self.assertEqual(keys, (session.fields['k1'], session.fields['k2']))

    def test_k2_is_not_replaced_by_k1_even_when_old_comparison_passed(self):
        session = self.session()
        session.run()
        session.fields['k2'] = b'x' * 32
        self.assertFalse(session.open_text_exchange().ready)

    def test_reset_archives_records_and_closes_previous_keys(self):
        session = self.session()
        session.run()
        old = session.open_text_exchange()
        old.send('A', 'first')
        new = session.open_text_exchange(reset=True)
        self.assertFalse(old.ready)
        self.assertTrue(new.ready)
        self.assertNotEqual(new.session_id, old.session_id)
        self.assertEqual(new.send('A', 'new')['sequence'], 0)
        self.assertEqual(session.text_exchanges[0]['records'][0]['received_text'], 'first')
        session.close()
        self.assertFalse(new.ready)

    def test_export_contains_rejections_and_previous_sessions(self):
        session = self.session()
        session.run()
        session.open_text_exchange().send('B', 'original', fault='tag')
        session.open_text_exchange(reset=True).send('A', 'verified')
        with tempfile.TemporaryDirectory() as directory:
            path = session.export(directory)
            data = json.loads((path / 'text_sessions.json').read_text(encoding='utf-8'))
            self.assertEqual(len(data), 2)
            self.assertFalse(data[0]['records'][0]['ok'])
            self.assertIsNone(data[0]['records'][0]['received_text'])
            self.assertEqual(data[1]['records'][0]['received_text'], 'verified')
            result = json.loads((path / 'result.json').read_text(encoding='utf-8'))
            self.assertEqual(result['text_session_count'], 2)
            self.assertTrue(result['result'])

    def test_concurrent_close_cannot_leave_a_usable_new_exchange(self):
        import text_crypto
        session = self.session()
        session.run()
        entered, release, closing, closed = (threading.Event() for _ in range(4))
        constructed, errors = [], []
        actual_constructor = text_crypto.TextExchange

        def constructor(*args, **kwargs):
            channel = actual_constructor(*args, **kwargs)
            constructed.append(channel)
            entered.set()
            if not release.wait(5): raise TimeoutError('test construction gate')
            return channel

        def opening():
            try: session.open_text_exchange()
            except Exception as exc: errors.append(exc)

        def disconnecting():
            closing.set()
            session.close()
            closed.set()

        with patch.object(text_crypto, 'TextExchange', side_effect=constructor):
            opener = threading.Thread(target=opening)
            closer = threading.Thread(target=disconnecting)
            opener.start()
            try:
                self.assertTrue(entered.wait(5))
                closer.start()
                self.assertTrue(closing.wait(5))
                closed.wait(.1)
            finally:
                release.set()
                opener.join(5)
                if closer.ident is not None: closer.join(5)
        self.assertFalse(errors)
        self.assertFalse(opener.is_alive())
        self.assertFalse(closer.is_alive())
        self.assertTrue(session._closed)
        self.assertTrue(all(not channel.ready for channel in constructed))

    def test_concurrent_reset_and_export_capture_one_consistent_inventory(self):
        session = self.session()
        session.run()
        session.open_text_exchange().send('A', 'first')
        archived, release, exporting = (threading.Event() for _ in range(3))
        errors, paths = [], []

        class PausedArchive(list):
            def append(self, item):
                super().append(item)
                archived.set()
                if not release.wait(5): raise TimeoutError('test archive gate')

        session.text_exchanges = PausedArchive()
        def reset():
            try: session.open_text_exchange(reset=True)
            except Exception as exc: errors.append(exc)
        with tempfile.TemporaryDirectory() as directory:
            def export():
                exporting.set()
                try: paths.append(session.export(directory))
                except Exception as exc: errors.append(exc)
            resetting = threading.Thread(target=reset)
            exporter = threading.Thread(target=export)
            resetting.start()
            try:
                self.assertTrue(archived.wait(5))
                exporter.start()
                self.assertTrue(exporting.wait(5))
                exporter.join(.1)
            finally:
                release.set()
                resetting.join(5)
                if exporter.ident is not None: exporter.join(5)
            self.assertFalse(errors)
            self.assertFalse(resetting.is_alive())
            self.assertFalse(exporter.is_alive())
            data = json.loads((paths[0] / 'text_sessions.json').read_text(encoding='utf-8'))
            self.assertEqual(len(data), 2)
            self.assertEqual(len({item['session_id'] for item in data}), 2)
