"""Real Tk behavior for the redesigned chat and image workflow."""
import contextlib
import gc
import hashlib
import io
import time
import tkinter as tk
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from PIL import Image

from gui import DemoApp
from image_utils import validate_image


def png_bytes(size=(48, 32)):
    stream = io.BytesIO()
    Image.new('RGB', size, (20, 110, 155)).save(stream, format='PNG')
    return stream.getvalue()


class GuiCommunicationTests(unittest.TestCase):
    def setUp(self):
        gc.collect()
        quiet = contextlib.redirect_stdout(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = DemoApp(self.root, simulate=True)
        self.panel = self.app.communication_panel
        self.addCleanup(self.cleanup_gui)

    def cleanup_gui(self):
        self.app.close()
        deadline = time.monotonic() + 20
        while not self.app.destroyed:
            self.root.update()
            if time.monotonic() > deadline:
                self.fail('GUI failed to wait for both workers')
            time.sleep(.003)
        self.panel = self.app = self.root = None
        gc.collect()

    def idle(self):
        deadline = time.monotonic() + 20
        while self.app.busy or self.panel.busy:
            self.root.update()
            if time.monotonic() > deadline:
                self.fail('GUI worker timeout')
            time.sleep(.003)
        self.root.update()

    def start(self):
        self.app.select_mode('communication')
        self.panel.connect()
        self.idle()
        self.assertIsNotNone(self.panel.session, self.panel.status_var.get())
        self.assertTrue(self.panel.session.ready, self.panel.status_var.get())
        return self.panel.session

    def send_text(self, role, value):
        self.panel.select_sender(role)
        self.panel.message_input.delete('1.0', 'end')
        self.panel.message_input.insert('1.0', value)
        self.panel.send_current()
        self.idle()

    def test_chat_layout_fixed_modes_no_version_and_no_fault_ui(self):
        self.assertNotIn('v3', self.root.title().lower())
        self.assertEqual(self.app.simulate_check.indicator.cget('text'), '✓')
        self.assertEqual(self.app.pause_transfer_check.indicator.cget('text'), '')
        self.app.pause_transfer_var.set(True)
        self.root.update()
        self.assertEqual(self.app.pause_transfer_check.indicator.cget('text'), '✓')
        inactive = self.app.communication_mode_button.cget('background')
        self.app.select_mode('communication')
        self.root.update()
        self.assertEqual(self.panel.chat_canvas.master.grid_info()['row'], 1)
        self.assertEqual(self.panel.composer_frame.grid_info()['row'], 3)
        self.assertNotIn('fault_var', vars(self.panel))
        self.assertNotIn('replay', self.panel.buttons)
        self.assertNotIn('enroll', self.panel.buttons)
        self.assertFalse(hasattr(self.panel, 'identity_path_var'))
        self.assertIs(self.panel.master, self.app.communication_page)
        self.root.geometry('1320x900')
        self.root.update()
        initial = (self.root.winfo_width(), self.root.winfo_height(),
                   self.app.demo_mode_button.winfo_width(), self.app.demo_mode_button.winfo_height())
        self.app.select_mode('communication')
        self.root.update()
        self.assertEqual(initial, (self.root.winfo_width(), self.root.winfo_height(),
                                   self.app.demo_mode_button.winfo_width(),
                                   self.app.demo_mode_button.winfo_height()))
        self.assertNotEqual(self.app.communication_mode_button.cget('background'), inactive)
        self.assertEqual(str(self.app.communication_page.winfo_manager()), 'grid')

    def test_communication_ports_refresh_and_select_independently(self):
        ports = [SimpleNamespace(device='COM7'), SimpleNamespace(device='COM8')]
        self.app.port1_var.set('COM1')
        self.app.port2_var.set('COM2')
        with patch('serial.tools.list_ports.comports', return_value=ports):
            found = self.panel.refresh_ports()
        self.assertEqual(found, ['COM7', 'COM8'])
        self.assertEqual(tuple(self.panel.port1_combo.cget('values')), ('COM7', 'COM8'))
        self.assertEqual((self.panel.port1_var.get(), self.panel.port2_var.get()),
                         ('COM7', 'COM8'))
        self.assertEqual((self.app.port1_var.get(), self.app.port2_var.get()), ('COM1', 'COM2'))

    def test_sidebar_resizes_hides_packet_details_and_clear_chat(self):
        session = self.start()
        self.root.geometry('1320x900+2400+1600')
        self.root.deiconify()
        self.root.update()
        self.panel.set_sidebar_width(410)
        self.root.update()
        self.assertGreaterEqual(self.panel.side_frame.winfo_width(), 400)
        self.assertLessEqual(self.panel.side_frame.winfo_width(), 420)
        for key in ('ports', 'connect', 'disconnect', 'rekey', 'export'):
            self.assertGreaterEqual(self.panel.buttons[key].winfo_width() + 1,
                                    self.panel.buttons[key].winfo_reqwidth())
        self.root.geometry('1120x780+2400+1600')
        self.panel.set_sidebar_width(280)
        self.root.update()
        for key in ('ports', 'connect', 'disconnect', 'rekey', 'export'):
            self.assertGreaterEqual(self.panel.buttons[key].winfo_width() + 1,
                                    self.panel.buttons[key].winfo_reqwidth())
        self.send_text('A', 'packet details')
        packet = self.panel.chat_records[-1]
        self.panel._show_packet(packet)
        self.root.update()
        details = self.panel.packet_text.get('1.0', 'end-1c')
        self.assertIn('Nonce:', details)
        self.assertIn('原始报文:', details)
        self.assertEqual(self.panel.side_notebook.select(), str(self.panel.packet_tab))
        records_before = len(session.exchange.history)
        self.assertFalse(self.panel.toggle_sidebar())
        self.root.update()
        self.assertFalse(self.panel.sidebar_visible)
        self.assertEqual(self.panel.sidebar_toggle_button.cget('text'), '显示侧栏')
        self.assertTrue(self.panel.toggle_sidebar())
        self.root.update()
        self.assertEqual(self.panel.sidebar_toggle_button.cget('text'), '隐藏侧栏')
        self.panel.clear_chat()
        self.assertEqual(self.panel.chat_records, [])
        self.assertEqual(self.panel.image_messages, [])
        self.assertEqual(self.panel.packet_text.get('1.0', 'end-1c'), '')
        self.assertEqual(len(session.exchange.history), records_before)
        self.assertIn('仍保留', self.panel.status_var.get())

    def test_one_click_chip1_signs_chip2_verifies_and_key_panel_reveals(self):
        session = self.start()
        epoch = session.epochs[0]
        self.assertTrue(epoch['session_signing_verified'])
        self.assertEqual([(p['signer'], p['verifier']) for p in epoch['proofs']],
                         [('A', 'B'), ('A', 'B')])
        self.assertIsNotNone(self.panel.key_data)
        masked = self.panel.key_text.get('1.0', 'end-1c')
        self.assertNotIn(self.panel.key_data['k_a_hex'], masked)
        self.assertIn(self.panel.key_data['k_a_fingerprint'], masked)
        self.panel.key_reveal_var.set(True)
        self.root.update()
        self.assertEqual(self.panel.key_reveal_check.indicator.cget('text'), '✓')
        self.panel._render_key_panel()
        revealed = self.panel.key_text.get('1.0', 'end-1c')
        for name in ('k_a_hex', 'k_b_hex', 'a_to_b_aes_hex', 'b_to_a_aes_hex'):
            self.assertIn(self.panel.key_data[name], revealed)
        self.panel.copy_keys()
        self.assertIn(self.panel.key_data['k_a_hex'], self.panel.clipboard_get())
        self.assertNotIn(self.panel.key_data['k_a_hex'], str(session.snapshot()))

    def test_text_chat_uses_single_timeline_and_bottom_send_box(self):
        self.start()
        self.send_text('A', '你好，聊天界面')
        self.send_text('B', '收到，这是回复')
        self.assertEqual([item['sender'] for item in self.panel.chat_records], ['A', 'B'])
        self.assertEqual([item['received_text'] for item in self.panel.chat_records],
                         ['你好，聊天界面', '收到，这是回复'])
        self.assertEqual(self.panel.message_input.get('1.0', 'end-1c'), '')

    def test_image_file_send_receive_preview_and_download(self):
        self.start()
        data = png_bytes()
        source = Path(self.temporary.name) / 'source.png'
        source.write_bytes(data)
        self.assertTrue(self.panel.attach_image_path(source))
        self.assertIsNotNone(self.panel.attachment)
        self.panel.send_current(); self.idle()
        self.assertEqual(len(self.panel.image_messages), 1)
        message = self.panel.image_messages[0]
        saved = Path(message['image_path'])
        self.assertTrue(saved.is_file())
        self.assertEqual(hashlib.sha256(saved.read_bytes()).hexdigest(), message['sha256'])
        self.assertIsNone(self.panel.attachment)
        self.panel._show_packet(message)
        self.root.update()
        choices = tuple(self.panel.packet_selector.cget('values'))
        chunk_choices = [choice for choice in choices if choice.startswith('数据块 ')]
        self.assertTrue(chunk_choices)
        self.panel.packet_choice_var.set(chunk_choices[0])
        self.panel._packet_choice_changed()
        details = self.panel.packet_text.get('1.0', 'end-1c')
        self.assertIn('Nonce:', details)
        self.assertIn('密文:', details)
        self.assertIn('原始报文:', details)
        self.assertIn('实际交付:', details)
        target = Path(self.temporary.name) / 'downloaded.png'
        with patch('communication_panel.filedialog.asksaveasfilename', return_value=str(target)):
            self.assertTrue(self.panel.download_image(saved, 'downloaded.png'))
        self.assertEqual(target.read_bytes(), data)
        viewer = self.panel.view_image(saved)
        self.assertIsInstance(viewer, tk.Toplevel)
        self.panel._close_view(viewer)

    def test_ctrl_v_pastes_validated_image_into_composer(self):
        self.start()
        data = png_bytes((60, 40))
        metadata = validate_image(data, 'clipboard.png')
        with patch('communication_panel.read_clipboard_image', return_value=(data, metadata)):
            result = self.panel._paste_event()
        self.assertEqual(result, 'break')
        self.assertIsNotNone(self.panel.attachment)
        self.assertEqual(self.panel.attachment[0], data)
        self.assertEqual(str(self.panel.attachment_frame.winfo_manager()), 'grid')

    def test_image_send_in_both_directions_survives_rekey_chat_history(self):
        self.start()
        for role in ('A', 'B'):
            source = Path(self.temporary.name) / f'{role}.png'
            source.write_bytes(png_bytes((30 + ord(role), 24)))
            self.panel.select_sender(role)
            self.assertTrue(self.panel.attach_image_path(source))
            self.panel.send_current(); self.idle()
        self.assertEqual(len(self.panel.image_messages), 2)
        old_key = self.panel.key_data['session_id_hex']
        old_paths = [Path(item['image_path']) for item in self.panel.image_messages]
        self.panel.rekey(); self.idle()
        self.assertNotEqual(old_key, self.panel.key_data['session_id_hex'])
        self.assertEqual(len(self.panel.image_messages), 2)
        self.assertTrue(all(path.is_file() for path in old_paths))

    def test_tab_switch_releases_sessions_and_close_waits_for_worker(self):
        self.app.start_run(); self.idle()
        demo = self.app.session
        self.app.select_mode('communication'); self.idle()
        self.assertIsNone(self.app.session)
        self.assertTrue(demo._closed)
        session = self.start()
        entered, release = threading.Event(), threading.Event()
        seen = []
        original = session.rekey
        def slow_rekey():
            seen.append(threading.get_ident())
            entered.set(); release.wait(5)
            return original()
        with patch.object(session, 'rekey', side_effect=slow_rekey) as rekey:
            self.panel.rekey()
            self.assertTrue(entered.wait(2))
            worker = self.panel.worker
            self.app.select_mode('demo')
            self.app.start_run()
            self.assertFalse(self.app.busy)
            self.app.close(); self.root.update()
            self.assertFalse(self.app.destroyed)
            release.set()
            deadline = time.monotonic() + 20
            while not self.app.destroyed:
                self.root.update()
                if time.monotonic() > deadline:
                    self.fail('close did not finish')
                time.sleep(.003)
            self.assertEqual(rekey.call_count, 1)
            self.assertNotEqual(seen, [threading.get_ident()])
            self.assertFalse(worker.is_alive())
            self.assertTrue(session.closed)
            self.assertTrue(self.panel.shutdown_complete)
            self.assertIsNone(self.panel._poll_id)
            self.assertIsNone(self.app._poll_id)


if __name__ == '__main__':
    unittest.main()
