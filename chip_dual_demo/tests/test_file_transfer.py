"""Binary image/file records over the authenticated record channel."""
import hashlib
import json
import unittest

import text_crypto as tc


class FileTransferTests(unittest.TestCase):
    def exchange(self):
        channel = tc.TextExchange(b'a' * 32, b'a' * 32, b'h' * 32, b'h' * 32)
        self.addCleanup(channel.close)
        return channel

    def test_file_send_receive_and_verified_payload(self):
        data = bytes(range(256)) * 400
        channel = self.exchange()
        result = channel.send_file('A', 'photo.png', 'image/png', data)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['file_size'], len(data))
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['received_sha256'], result['sha256'])
        self.assertEqual(result['file_name'], 'photo.png')
        self.assertEqual(channel.payload(result['payload_id']), data)

    def test_both_directions_use_independent_sequences(self):
        data = b'\x89PNG\r\n\x1a\n' + b'x' * 1000
        channel = self.exchange()
        first = channel.send_file('A', 'same.png', 'image/png', data)
        second = channel.send_file('B', 'same.png', 'image/png', data)
        self.assertTrue(first['ok'] and second['ok'])
        self.assertNotEqual(first['payload_id'], second['payload_id'])
        self.assertEqual(channel.payload(first['payload_id']), data)
        self.assertEqual(channel.payload(second['payload_id']), data)

    def test_faults_never_publish_a_file_payload(self):
        data = b'image-image' * 10000
        for fault in ('file_chunk_tag', 'file_chunk_ciphertext', 'file_digest',
                      'file_drop', 'file_reorder', 'file_drop_end', 'file_end_tag'):
            with self.subTest(fault=fault):
                channel = self.exchange()
                result = channel.send_file('A', 'x.png', 'image/png', data, fault=fault)
                self.assertFalse(result['ok'], fault)
                self.assertFalse(channel.ready)
                self.assertNotIn('payload_id', result)
                self.assertIsNone(result.get('received_sha256'))

    def test_invalid_name_and_oversize_are_rejected_without_closing(self):
        channel = self.exchange()
        with self.assertRaises(ValueError):
            channel.send_file('A', '../evil.png', 'image/png', b'data')
        with self.assertRaises(ValueError):
            channel.send_file('A', 'large.png', 'image/png', b'x' * (tc.MAX_FILE_BYTES + 1))
        self.assertTrue(channel.ready)
        result = channel.send_file('A', 'valid.png', 'image/png', b'data')
        self.assertTrue(result['ok'])

    def test_export_has_metadata_but_no_binary_payload_or_raw_keys(self):
        data = b'secret image bytes' * 20
        channel = self.exchange()
        result = channel.send_file('A', 'photo.png', 'image/png', data)
        self.assertEqual(len(result['packet_details']), result['chunk_count'] + 2)
        for packet in result['packet_details']:
            self.assertEqual(
                packet['header_hex'] + packet['ciphertext_hex'] + packet['tag_hex'],
                packet.get('delivered_packet_hex',
                           packet['header_hex'] + packet['ciphertext_hex'] + packet['tag_hex']))
            self.assertEqual(len(packet['nonce_hex']), 24)
        exported = channel.export_data()
        rendered = json.dumps(exported)
        self.assertIn(result['sha256'], rendered)
        self.assertNotIn(data.hex().upper(), rendered)
        self.assertNotIn(result['packet_details'][0]['ciphertext_hex'], rendered)
        self.assertTrue(exported['records'][0]['packet_details_available_in_ui'])
        for forbidden in ('a_to_b_aes_hex', 'b_to_a_aes_hex', 'shared_secret'):
            self.assertNotIn(forbidden, rendered)

    def test_key_material_for_ui_is_not_exported_and_is_cleared_on_close(self):
        channel = self.exchange()
        keys = channel.key_material()
        self.assertEqual(len(bytes.fromhex(keys['k_a_hex'])), 32)
        self.assertEqual(len(bytes.fromhex(keys['k_b_hex'])), 32)
        self.assertEqual(len(bytes.fromhex(keys['a_to_b_aes_hex'])), 32)
        self.assertEqual(len(bytes.fromhex(keys['b_to_a_aes_hex'])), 32)
        self.assertNotEqual(keys['a_to_b_aes_hex'], keys['b_to_a_aes_hex'])
        self.assertNotIn('a_to_b_aes_hex', json.dumps(channel.export_data()))
        channel.close()
        with self.assertRaises(tc.TextSecurityError):
            channel.key_material()

    def test_text_and_file_records_share_the_directional_sequence(self):
        channel = self.exchange()
        text = channel.send('A', 'before image')
        image = channel.send_file('A', 'one.png', 'image/png', b'\x89PNG\r\n\x1a\n' + b'x' * 1000)
        after = channel.send('A', 'after image')
        self.assertEqual(text['sequence'], 0)
        self.assertEqual(image['first_sequence'], 1)
        self.assertEqual(after['sequence'], image['last_sequence'] + 1)


if __name__ == '__main__':
    unittest.main()
