"""Behavioral checks, including independent library interoperability."""
import hmac
import struct
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import text_crypto as tc


class TextCryptoTests(unittest.TestCase):
    def endpoints(self, **overrides):
        args = dict(secret=bytes(range(32)), session_id=b's' * 16,
                    salt=b'z' * 32, transcript=b'h' * 32)
        args.update(overrides)
        a, b = tc.SecureEndpoint('A', **args), tc.SecureEndpoint('B', **args)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.verify_confirmation(b.confirmation())
        b.verify_confirmation(a.confirmation())
        return a, b

    def exchange(self):
        channel = tc.TextExchange(b'k' * 32, b'k' * 32, b'h' * 32, b'h' * 32)
        self.addCleanup(channel.close)
        return channel

    def test_record_decrypts_with_independently_derived_aes_key(self):
        a, b = self.endpoints()
        packet = a.encrypt('芯片A → B'.encode())
        size = struct.calcsize('!4sBBB16sQI')
        header, encrypted = packet[:size], packet[size:]
        self.assertEqual(struct.unpack('!4sBBB16sQI', header),
                         (b'LC3T', 1, 1, 0, b's' * 16, 0, len(encrypted)))
        context = b'LC01-TEXT-v1\x00' + b's' * 16 + b'h' * 32
        key = HKDF(hashes.SHA256(), 32, b'z' * 32, context + b'\x00A>B/aes').derive(bytes(range(32)))
        prefix = HKDF(hashes.SHA256(), 4, b'z' * 32, context + b'\x00A>B/nonce').derive(bytes(range(32)))
        self.assertEqual(AESGCM(key).decrypt(prefix + bytes(8), encrypted, header), '芯片A → B'.encode())
        self.assertEqual(b.decrypt(packet), '芯片A → B'.encode())
        reverse = b.encrypt(b'reply')
        self.assertEqual(a.decrypt(reverse), b'reply')
        with self.assertRaises(Exception):
            AESGCM(key).decrypt(prefix + bytes(8), reverse[size:], reverse[:size])

    def test_confirmation_is_separate_directional_hmac_and_required(self):
        a = tc.SecureEndpoint('A', b'k' * 32, b's' * 16, b'z' * 32, b'h' * 32)
        self.addCleanup(a.close)
        context = b'LC01-TEXT-v1\x00' + b's' * 16 + b'h' * 32
        key = HKDF(hashes.SHA256(), 32, b'z' * 32, context + b'\x00A>B/confirm').derive(b'k' * 32)
        expected = hmac.digest(key, b'LC01-FINISHED-v1\x00' + context + b'\x00A>B', 'sha256')
        self.assertEqual(a.confirmation(), expected)
        with self.assertRaises(tc.TextSecurityError): a.encrypt(b'before confirmation')
        with self.assertRaises(tc.TextSecurityError): a.verify_confirmation(a.confirmation())

    def test_wrong_secret_or_transcript_does_not_enable_exchange(self):
        for secret, transcript in ((b'x' * 32, b'h' * 32), (b'k' * 32, b'x' * 32)):
            channel = tc.TextExchange(b'k' * 32, secret, b'h' * 32, transcript)
            self.addCleanup(channel.close)
            self.assertFalse(channel.ready)
            with self.assertRaises(tc.TextSecurityError): channel.send('A', '不得发送')
            self.assertEqual(channel.history, [])

    def test_unicode_empty_boundary_and_independent_sequence_spaces(self):
        a, b = self.endpoints()
        for message in (b'', '双向通信\n🙂'.encode(), b'x' * 65536):
            self.assertEqual(b.decrypt(a.encrypt(message)), message)
            self.assertEqual(a.decrypt(b.encrypt(message)), message)
        with self.assertRaises(ValueError): a.encrypt(b'x' * 65537)
        self.assertEqual(b.decrypt(a.encrypt(b'after rejected oversize')), b'after rejected oversize')

    def test_ciphertext_tag_and_authenticated_header_modifications_rejected(self):
        for offset in (35, -1, 5):
            with self.subTest(offset=offset):
                a, b = self.endpoints()
                packet = bytearray(a.encrypt(b'secret text'))
                packet[offset] ^= 1
                with self.assertRaises(tc.TextSecurityError): b.decrypt(bytes(packet))
                with self.assertRaises(tc.TextSecurityError): b.decrypt(a.encrypt(b'later'))

    def test_replay_skipped_sequence_wrong_direction_and_other_session_rejected(self):
        a, b = self.endpoints()
        packet = a.encrypt(b'first')
        self.assertEqual(b.decrypt(packet), b'first')
        with self.assertRaises(tc.TextSecurityError) as error: b.decrypt(packet)
        self.assertEqual(error.exception.code, 'sequence_error')
        a, b = self.endpoints()
        a.encrypt(b'lost')
        with self.assertRaises(tc.TextSecurityError): b.decrypt(a.encrypt(b'skipped'))
        a, b = self.endpoints()
        with self.assertRaises(tc.TextSecurityError): a.decrypt(a.encrypt(b'reflection'))
        a, b = self.endpoints()
        foreign, _ = self.endpoints(session_id=b't' * 16)
        with self.assertRaises(tc.TextSecurityError): b.decrypt(foreign.encrypt(b'other'))

    def test_truncation_extra_bytes_and_short_headers_are_rejected(self):
        for mutate in (lambda p: p[:10], lambda p: p[:-1], lambda p: p + b'x'):
            a, b = self.endpoints()
            with self.assertRaises(tc.TextSecurityError): b.decrypt(mutate(a.encrypt(b'text')))

    def test_limits_and_close_never_reset_counter_under_same_key(self):
        a, b = self.endpoints()
        a._tx_sequence = tc.MAX_RECORDS
        with self.assertRaises(tc.TextSecurityError): a.encrypt(b'overflow')
        a, b = self.endpoints()
        a._tx_bytes = tc.MAX_SESSION_BYTES
        with self.assertRaises(tc.TextSecurityError): a.encrypt(b'overflow')
        a, b = self.endpoints()
        packet = a.encrypt(b'text')
        a.close()
        with self.assertRaises(tc.TextSecurityError): a.encrypt(b'closed')
        b.close()
        with self.assertRaises(tc.TextSecurityError): b.decrypt(packet)

    def test_exchange_fault_preserves_packets_but_never_delivers_plaintext(self):
        for fault in ('ciphertext', 'tag', 'header'):
            channel = self.exchange()
            record = channel.send('A', '保密内容', fault=fault)
            self.assertFalse(record['ok'])
            self.assertIsNone(record['received_text'])
            self.assertNotEqual(record['original_packet_hex'], record['delivered_packet_hex'])
            self.assertFalse(channel.ready)
            with self.assertRaises(tc.TextSecurityError): channel.send('B', 'blocked')

    def test_replay_is_recorded_as_rejected_and_new_session_has_new_keys(self):
        first, second = self.exchange(), self.exchange()
        self.assertNotEqual(first.session_id, second.session_id)
        one = first.send('A', 'hello')
        two = first.send('B', '你好')
        self.assertEqual((one['received_text'], two['received_text']), ('hello', '你好'))
        replay = first.replay_last()
        self.assertFalse(replay['ok'])
        self.assertEqual(replay['error_code'], 'sequence_error')
        self.assertIsNone(replay['received_text'])
        exported = first.export_data()
        self.assertFalse(exported['session_signing_verified'])
        self.assertEqual(exported['transport'], 'in_process')
        self.assertEqual(len(exported['records']), 3)
        self.assertNotIn('secret', exported)

    def test_transcript_encoding_is_unambiguous_and_binds_every_field(self):
        value = tc.transcript_hash('kyber512', b'pk', b'ct')
        self.assertEqual(len(value), 32)
        for args in (('kyber768', b'pk', b'ct'), ('kyber512', b'p', b'kct'), ('kyber512', b'pk', b'cx')):
            self.assertNotEqual(value, tc.transcript_hash(*args))

    def test_invalid_endpoint_parameters_rejected(self):
        for role, secret, sid, salt, transcript in (
                ('C', b'k' * 32, b's' * 16, b'z' * 32, b'h' * 32),
                ('A', b'k' * 31, b's' * 16, b'z' * 32, b'h' * 32),
                ('A', b'k' * 32, b's' * 15, b'z' * 32, b'h' * 32)):
            with self.assertRaises(ValueError): tc.SecureEndpoint(role, secret, sid, salt, transcript)

    def test_unexpected_backend_failure_closes_both_endpoints_and_is_exported(self):
        channel = self.exchange()
        with patch.object(channel._a, 'encrypt', side_effect=RuntimeError('backend failed')):
            with self.assertRaisesRegex(RuntimeError, 'backend failed'): channel.send('A', 'text')
        self.assertFalse(channel.ready)
        self.assertTrue(channel._a.closed and channel._b.closed)
        data = channel.export_data()
        self.assertTrue(data['closed'])
        self.assertEqual(data['terminal_error']['code'], 'encryption_error')
        self.assertEqual(data['records'], [])

    def test_oversized_input_is_rejected_before_consuming_nonce_or_closing_session(self):
        channel = self.exchange()
        with self.assertRaises(ValueError): channel.send('A', 'x' * 65537)
        self.assertTrue(channel.ready)
        self.assertEqual(channel.send('A', 'valid')['sequence'], 0)

    def test_unexpected_decrypt_failure_preserves_attempted_delivery_without_plaintext(self):
        channel = self.exchange()
        with patch.object(channel._b, 'decrypt', side_effect=RuntimeError('backend failed')):
            with self.assertRaisesRegex(RuntimeError, 'backend failed'): channel.send('A', 'text')
        data = channel.export_data()
        self.assertTrue(data['closed'])
        self.assertEqual(data['terminal_error']['code'], 'decryption_error')
        self.assertEqual(len(data['records']), 1)
        self.assertEqual(data['records'][0]['error_code'], 'internal_error')
        self.assertIsNone(data['records'][0]['received_text'])
        self.assertEqual(data['records'][0]['original_packet_hex'], data['records'][0]['delivered_packet_hex'])
