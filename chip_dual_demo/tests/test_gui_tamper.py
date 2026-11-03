"""Real Tk integration: preview, actual simulated delivery and honest failure UI."""
import contextlib
import gc
import io
import sys
import time
import tkinter as tk
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gui import DemoApp


class GuiTamperTests(unittest.TestCase):
    def setUp(self):
        # Cycles from an earlier test must be collected before a serial worker can
        # trigger automatic GC. Tcl variables may only be finalized on this thread.
        gc.collect()
        self.app = None
        self.root = None
        self._editors = []
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()
        self.addCleanup(self.output.__exit__, None, None, None)
        self.addCleanup(self.cleanup_gui)  # Also covers a partially failed setUp.
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = DemoApp(self.root, simulate=True)

    def tearDown(self):
        self.cleanup_gui()

    def cleanup_gui(self):
        app, root = self.app, self.root
        editors = self._editors
        self._editors = []
        workers = set()
        try:
            if app is not None:
                if app.worker is not None:
                    workers.add(app.worker)
                app.close()
                deadline = time.monotonic() + 15
                while not app.destroyed:
                    if app.worker is not None:
                        workers.add(app.worker)
                    root.update()
                    if time.monotonic() > deadline:
                        self.fail('GUI failed to release its worker/window')
                    time.sleep(0.003)
                for worker in workers:
                    worker.join(timeout=max(0, deadline - time.monotonic()))
                    self.assertFalse(worker.is_alive(), 'GUI worker survived window cleanup')
            elif root is not None:
                root.destroy()
        finally:
            # Clear both test-owned references and locals *before* collecting.
            # Session emit/work closures and editor callbacks can retain DemoApp,
            # its Tk Variables and its Tcl interpreter after destroy().
            self.app = None
            self.root = None
            editors.clear()
            workers.clear()
            app = root = worker = None
            gc.collect()

    def open_editor(self):
        editor = self.app.open_transfer_editor()
        self._editors.append(editor)
        return editor

    def idle(self):
        deadline = time.monotonic() + 15
        while self.app.busy:
            self.root.update()
            if time.monotonic() > deadline:
                self.fail('simulated worker timeout')
            time.sleep(0.003)
        self.root.update()
        self.assertFalse(self.app.last_error, self.app.last_error)

    def pause_at_transfer(self, algorithm):
        self.app.select_algorithm(algorithm)
        self.app.pause_transfer_var.set(True)
        self.app.start_run()
        self.idle()
        if algorithm.startswith('kyber'):
            self.assertEqual(self.app.session.waiting_for_transfer, 2)
            self.assertNotIn('received_pk', self.app.fields)
            self.app.start_run()
            self.idle()
            self.assertEqual(self.app.session.waiting_for_transfer, 4)
            self.assertNotIn('received_ct', self.app.fields)
        else:
            self.assertEqual(self.app.session.waiting_for_transfer, 3)
            self.assertNotIn('received_signature', self.app.fields)
        self.assertIn('发送前暂停', self.app.status_var.get())
        self.assertTrue(self.app.buttons['tamper'].instate(['!disabled']))

    def assert_byte_zero_highlight(self, name):
        widget = self.app.field_widgets[name]
        self.assertEqual(tuple(map(str, widget.tag_ranges('diff'))), ('1.0', '1.2'))
        self.assertEqual(widget.get('1.0', 'end-1c'), self.app.fields[name].hex().upper())

    def test_ct_edit_is_preview_until_applied_and_actual_failure_completes(self):
        self.pause_at_transfer('kyber512')
        editor = self.open_editor()
        self.assertEqual(editor.current_name, 'ct')
        self.assertIs(self.root.grab_current(), editor.window)
        self.assertTrue(self.app.buttons['run'].instate(['disabled']))
        self.app.start_run()
        self.assertFalse(self.app.busy, 'modal editing must prevent programmatic concurrent launch')
        original = self.app.fields['ct']
        editor.offset_var.set('0x0')
        editor.mask_var.set('01')
        self.assertTrue(editor.flip_byte())
        self.assertEqual(editor.changed_offsets, [0])
        self.assertEqual(self.app.session.pending_transfers['ct'], original)
        self.assertEqual(tuple(map(str, editor.edit_text.tag_ranges('diff'))), ('1.0', '1.2'))
        self.assertTrue(editor.continue_run())
        self.idle()
        self.assertIsNone(self.app.transfer_editor)
        self.assertEqual(self.app.fields['ct'], original)
        self.assertEqual(self.app.fields['received_ct'], bytes([original[0] ^ 1]) + original[1:])
        self.assertIs(self.app.result, False)
        self.assertFalse(self.app.session._failed)
        self.assertTrue(all(self.app.step_states[i] == 'done' for i in range(len(self.app.steps))))
        self.assertIn('篡改后实际结果', self.app.result_text.get())
        self.assert_byte_zero_highlight('ct')
        self.assert_byte_zero_highlight('received_ct')
        self.app.left_notebook.select(self.app.field_tabs['received_ct'][1])
        self.root.update()
        self.assertEqual(self.app.right_notebook.select(), str(self.app.field_tabs['ct'][1]))
        self.app.copy_field('received_ct')
        self.assertEqual(self.root.clipboard_get(), self.app.fields['received_ct'].hex().upper())

    def test_signature_rejection_is_result_and_sent_history_is_readonly(self):
        self.pause_at_transfer('dilithium2')
        editor = self.open_editor()
        editor.select_field('signature')
        original = self.app.fields['signature']
        self.assertTrue(editor.flip_byte())
        self.assertTrue(editor.continue_run())
        self.idle()
        self.assertIs(self.app.result, False)
        self.assertFalse(self.app.session._failed)
        self.assertEqual(self.app.fields['signature'], original)
        self.assert_byte_zero_highlight('signature')
        self.assert_byte_zero_highlight('received_signature')
        self.assertFalse(self.app.field_widgets['received_message'].tag_ranges('diff'))
        self.assertIn('与对端一致', self.app.field_lengths['received_message'].get())
        self.assertEqual(self.app.result_text.get().count('篡改后实际结果'), 1)
        history = self.open_editor()
        history.select_field('signature')
        self.assertFalse(history.editable)
        self.assertEqual(str(history.edit_text['state']), 'disabled')
        self.assertIn('已获响应', history.right_title_var.get())
        sent = self.app.fields['received_signature']
        self.assertFalse(history.flip_byte())
        self.assertFalse(history.apply())
        self.assertEqual(self.app.fields['received_signature'], sent)
        history.close()

    def test_invalid_hex_length_and_offset_do_not_change_saved_transfer(self):
        self.pause_at_transfer('kyber512')
        editor = self.open_editor()
        original = self.app.session.pending_transfers['ct']
        for invalid in ('ZZ', '00'):
            editor.edit_text.delete('1.0', 'end')
            editor.edit_text.insert('1.0', invalid)
            self.root.update()
            self.assertFalse(editor.apply())
            self.assertFalse(editor.continue_run())
            self.assertFalse(self.app.busy)
            self.assertEqual(self.app.session.pending_transfers['ct'], original)
            self.assertEqual(self.app.fields['ct'], original)
        self.assertTrue(editor.reset())
        editor.offset_var.set(str(len(original)))
        self.assertFalse(editor.flip_byte())
        editor.offset_var.set('0')
        editor.mask_var.set('100')
        self.assertFalse(editor.flip_byte())
        self.assertEqual(self.app.session.pending_transfers['ct'], original)
        editor.mask_var.set('01')
        self.assertTrue(editor.flip_byte())
        self.assertTrue(editor.apply())
        self.assertNotEqual(self.app.session.pending_transfers['ct'], original)
        self.assertTrue(editor.reset())
        self.assertEqual(self.app.session.pending_transfers['ct'], original)
        self.assertFalse(editor.edit_text.tag_ranges('diff'))
        self.assertTrue(editor.continue_run())
        self.idle()
        self.assertIs(self.app.result, True)
        self.assertNotIn('篡改后实际结果', self.app.result_text.get())
        self.assertFalse(self.app.field_widgets['ct'].tag_ranges('diff'))

    def test_normal_received_fields_match_without_tamper_pause(self):
        self.assertFalse(self.app.pause_transfer_var.get())
        self.assertTrue(self.app.buttons['tamper'].instate(['disabled']))
        self.app.select_algorithm('dilithium2')
        self.app.start_run()
        self.idle()
        self.assertIs(self.app.result, True)
        for source in ('pk', 'signature', 'message'):
            received = 'received_' + source
            self.assertEqual(self.app.fields[source], self.app.fields[received])
            self.assertEqual(self.app.field_widgets[received].get('1.0', 'end-1c'),
                             self.app.fields[received].hex().upper())
            self.assertFalse(self.app.field_widgets[received].tag_ranges('diff'))
            self.assertIn('与对端一致', self.app.field_lengths[received].get())


if __name__ == '__main__':
    unittest.main()
