"""Entry point for source and PyInstaller builds."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


def screenshot(root, destination):
    """Optional Pillow capture. Nothing is captured or written without --screenshot."""
    from PIL import ImageGrab
    root.update_idletasks()
    root.update()
    image = None
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes

        class BitmapInfoHeader(ctypes.Structure):
            _fields_ = [('biSize', wintypes.DWORD), ('biWidth', wintypes.LONG),
                        ('biHeight', wintypes.LONG), ('biPlanes', wintypes.WORD),
                        ('biBitCount', wintypes.WORD), ('biCompression', wintypes.DWORD),
                        ('biSizeImage', wintypes.DWORD), ('biXPelsPerMeter', wintypes.LONG),
                        ('biYPelsPerMeter', wintypes.LONG), ('biClrUsed', wintypes.DWORD),
                        ('biClrImportant', wintypes.DWORD)]

        class BitmapInfo(ctypes.Structure):
            _fields_ = [('bmiHeader', BitmapInfoHeader),
                        ('bmiColors', wintypes.DWORD * 3)]

        window = ctypes.windll.user32.GetParent(root.winfo_id())
        rect = wintypes.RECT()
        if ctypes.windll.user32.GetWindowRect(window, ctypes.byref(rect)):
            width, height = rect.right - rect.left, rect.bottom - rect.top
            window_dc = ctypes.windll.user32.GetWindowDC(window)
            memory_dc = ctypes.windll.gdi32.CreateCompatibleDC(window_dc)
            bitmap = ctypes.windll.gdi32.CreateCompatibleBitmap(window_dc, width, height)
            previous = ctypes.windll.gdi32.SelectObject(memory_dc, bitmap)
            try:
                if ctypes.windll.user32.PrintWindow(window, memory_dc, 2):
                    info = BitmapInfo()
                    info.bmiHeader.biSize = ctypes.sizeof(BitmapInfoHeader)
                    info.bmiHeader.biWidth = width
                    info.bmiHeader.biHeight = -height
                    info.bmiHeader.biPlanes = 1
                    info.bmiHeader.biBitCount = 32
                    pixels = ctypes.create_string_buffer(width * height * 4)
                    rows = ctypes.windll.gdi32.GetDIBits(
                        memory_dc, bitmap, 0, height, pixels, ctypes.byref(info), 0)
                    if rows == height:
                        from PIL import Image
                        image = Image.frombuffer(
                            'RGB', (width, height), pixels, 'raw', 'BGRX', 0, 1).copy()
            finally:
                ctypes.windll.gdi32.SelectObject(memory_dc, previous)
                ctypes.windll.gdi32.DeleteObject(bitmap)
                ctypes.windll.gdi32.DeleteDC(memory_dc)
                ctypes.windll.user32.ReleaseDC(window, window_dc)
    if image is None:
        x, y = root.winfo_rootx(), root.winfo_rooty()
        bounds = (x, y, x + root.winfo_width(), y + root.winfo_height())
        image = ImageGrab.grab(bbox=bounds, all_screens=True)
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path)
    print(f'SCREENSHOT: {path}', flush=True)


def smoke_test(root, app, screenshot_path=None):
    """Exercise real Tk event delivery, controls and simulated core, with exit status."""
    from profiles import PROFILES

    def wait_idle(seconds=45):
        deadline = time.monotonic() + seconds
        while app.busy:
            root.update()
            if time.monotonic() > deadline:
                raise TimeoutError('GUI smoke-test worker timeout')
            time.sleep(0.005)
        root.update()

    for family in ('kem', 'signature'):
        key = next(key for key, profile in PROFILES.items() if profile.family == family)
        app.select_algorithm(key)
        app.simulate_var.set(True)
        app._mode_changed()
        before = dict(app.events_seen)
        app.connect()
        wait_idle()
        assert app.session is not None and app.session.next_step == 1, '初始化须只执行第一步'
        app.start_step()
        wait_idle()
        assert app.session.next_step == 2, '单步须执行且仅执行下一步'
        assert app.fields.get('pk') and app.fields.get('sk'), '公私钥字段未更新'
        app.start_run()
        wait_idle()
        assert not app.last_error, app.last_error
        assert app.result is True and app.session.result is True, '模拟流程未成功完成'
        assert app.session.next_step == len(app.session.steps), '步骤未全部完成'
        assert '通过' in app.result_text.get(), 'GUI结果标签未更新'
        assert all(app.step_states.get(i) == 'done' for i in range(len(app.steps))), '步骤控件未完成'
        required = ('pk', 'sk', 'ct', 'k1', 'k2') if family == 'kem' else ('pk', 'sk', 'message', 'signature', 'verify_response')
        for name in required:
            data = app.session.fields[name]
            assert app.fields[name] == data, f'{name} 事件数据不一致'
            assert app.field_widgets[name].get('1.0', 'end-1c') == data.hex().upper(), f'{name} 控件内容不完整'
        for event in ('field', 'step', 'result'):
            assert app.events_seen[event] > before[event], f'GUI 未消费 {event} 事件'
        assert app.buttons['run'].instate(['disabled']), '完成后须防止重复运行'
        print(f'SMOKE PASS: {family} / {key} / fields={len(required)} / steps={len(app.steps)}', flush=True)
        if screenshot_path and family == 'signature':
            root.deiconify()
            root.update()
            path = Path(screenshot_path)
            screenshot(root, path.with_name(path.stem + '_demo' + path.suffix))
            root.withdraw()
        app.disconnect()
        wait_idle()
        assert app.session is None, '断开后未清理 session 引用'
    for family in ('kem', 'signature'):
        key = next(key for key, profile in PROFILES.items() if profile.family == family)
        app.select_algorithm(key)
        app.pause_transfer_var.set(True)
        app.start_run()
        wait_idle()
        if family == 'kem':
            assert app.session.waiting_for_transfer == 2, '公钥发送前未暂停'
            app.start_run()
            wait_idle()
            assert app.session.waiting_for_transfer == 4, '密文发送前未暂停'
        else:
            assert app.session.waiting_for_transfer == 3, '签名生成后未暂停'
        name = 'ct' if family == 'kem' else 'signature'
        original = app.session.fields[name]
        modified = bytes([original[0] ^ 1]) + original[1:]
        editor = app.open_transfer_editor()
        assert editor is not None, '篡改编辑器未打开'
        editor.select_field(name)
        editor.offset_var.set('0')
        editor.mask_var.set('01')
        assert editor.flip_byte(), '编辑器字节翻转失败'
        assert app.session.pending_transfers[name] == original, '预览不能提前修改发送副本'
        assert editor.continue_run(), '编辑器应用并继续执行失败'
        wait_idle()
        assert not app.last_error, app.last_error
        assert app.result is False and app.session.result is False, '必须保留篡改后的实际失败结果'
        assert not app.session._failed, '字段差异或验签失败不得当成通信中断'
        assert app.session.next_step == len(app.session.steps)
        assert app.fields[name] == original
        assert app.fields['received_' + name] == modified
        for field in (name, 'received_' + name):
            tags = tuple(str(index) for index in app.field_widgets[field].tag_ranges('diff'))
            assert tags == ('1.0', '1.2'), f'{field} 应仅标红第0字节：{tags}'
        assert app.fields['received_pk'] == app.fields['pk']
        print(f'SMOKE PASS: tamper {family} / editor apply-and-continue / actual failed result / complete workflow / exact byte highlights', flush=True)
        app.disconnect()
        wait_idle()
    app.pause_transfer_var.set(False)
    # Same-window chip-1 signature verification, fresh chip KEM rekeying and
    # authenticated conversation.
    import hashlib
    import json
    import tempfile
    panel = app.communication_panel

    def wait_communication(seconds=60):
        deadline = time.monotonic() + seconds
        while app.busy or panel.busy:
            root.update()
            if time.monotonic() > deadline:
                raise TimeoutError('v3.2 communication worker timeout')
            time.sleep(0.005)
        root.update()

    def send_panel(role, message):
        panel.select_sender(role)
        panel.message_input.delete('1.0', 'end')
        panel.message_input.insert('1.0', message)
        panel.send_current()
        wait_communication()
        assert panel.chat_records, panel.status_var.get()
        return panel.chat_records[-1]

    with tempfile.TemporaryDirectory(prefix='LC01_v31_smoke_') as directory:
        assert app.select_mode('communication')
        root.update()
        panel.connect()
        wait_communication()
        assert panel.session is not None and panel.session.ready, panel.status_var.get()
        session = panel.session
        assert session.epochs[0]['session_signing_verified']
        assert session.epochs[0]['stored_signing_credentials'] is False
        assert all(proof['verified'] for proof in session.epochs[0]['proofs'])
        assert [(proof['signer'], proof['verifier']) for proof in session.epochs[0]['proofs']] == [('A', 'B'), ('A', 'B')]
        assert not session.epochs[0]['direct_k_comparison']
        assert send_panel('A', 'A→B 中文认证加密')['received_text'] == 'A→B 中文认证加密'
        assert send_panel('B', 'B→A 回复')['received_text'] == 'B→A 回复'
        from PIL import Image, ImageDraw
        image_path = Path(directory) / 'smoke-chat.png'
        image = Image.new('RGB', (640, 360), '#D8EFF2')
        ImageDraw.Draw(image).rounded_rectangle((80, 70, 560, 290), radius=28, fill='#135C75')
        ImageDraw.Draw(image).text((250, 165), 'LC01 secure image', fill='white')
        image.save(image_path)
        original_image = image_path.read_bytes()
        panel.select_sender('A')
        assert panel.attach_image_path(image_path)
        panel.send_current()
        wait_communication()
        assert panel.image_messages, panel.status_var.get()
        image_message = panel.image_messages[-1]
        received_image = Path(image_message['image_path'])
        assert received_image.is_file()
        assert hashlib.sha256(original_image).hexdigest() == image_message['sha256']
        assert received_image.read_bytes() == original_image
        assert panel.key_data is not None and panel.key_data['both_directions_confirmed']
        old_exchange = session.exchange
        panel.rekey()
        wait_communication()
        assert session.ready and len(session.epochs) == 2
        assert not old_exchange.ready
        assert session.exchange.session_id != old_exchange.session_id
        assert send_panel('B', '重新建钥后的对话')['sequence'] == 0
        if screenshot_path:
            root.deiconify()
            app.select_mode('communication')
            panel.set_sidebar_width(410)
            root.update()
            path = Path(screenshot_path)
            screenshot(root, path.with_name(path.stem + '_v3.2' + path.suffix))
            panel._show_packet(image_message)
            chunk_choices = [choice for choice in panel.packet_selector.cget('values')
                             if choice.startswith('数据块 ')]
            assert chunk_choices, '图片报文明细缺少数据块'
            panel.packet_choice_var.set(chunk_choices[0])
            panel._packet_choice_changed()
            root.update()
            screenshot(root, path.with_name(path.stem + '_v3.2_packet' + path.suffix))
            root.withdraw()
        panel.export(directory)
        assert panel.last_export is not None and panel.last_export.is_dir()
        exported = json.loads((panel.last_export / 'communication.json').read_text(encoding='utf-8'))
        assert len(exported['epochs']) == 2
        assert all(item['session_signing_verified'] for item in exported['epochs'])
        assert all(item['stored_signing_credentials'] is False for item in exported['epochs'])
        assert not exported['direct_k_comparison']
        assert any(item['kind'] == 'file' for item in exported['text_sessions'][0]['records'])
        assert panel.key_data['k_a_hex'] not in json.dumps(exported)
        trace = json.loads((panel.last_export / 'command_trace.json').read_text(encoding='utf-8'))
        assert any(item.get('tx_redacted') or item.get('rx_redacted') for item in trace)
        panel.disconnect()
        assert session.closed
    assert app.select_mode('demo')
    root.update()
    print('SMOKE PASS: chat UI / chip1 signs + chip2 verifies / text+image AEAD / image hash+preview / key inspector / fresh KEM', flush=True)
    print('SMOKE PASS: real Tk events, original/received fields, tamper continuation and session cleanup', flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description='LC01 双芯片桌面演示')
    parser.add_argument('--simulate', action='store_true', help='显式启用流程模拟，不连接硬件')
    parser.add_argument('--smoke-test', action='store_true', help='隐藏窗口运行双模式 GUI 模拟测试，成功返回0')
    parser.add_argument('--screenshot', metavar='PATH', help='可选：使用 Pillow 将窗口截图保存到指定路径')
    args = parser.parse_args(argv)
    import tkinter as tk
    from gui import DemoApp

    root = tk.Tk()
    if args.smoke_test:
        root.withdraw()
    app = DemoApp(root, simulate=args.simulate or args.smoke_test)
    if args.smoke_test:
        code = 0
        try:
            smoke_test(root, app, args.screenshot)
        except Exception as exc:
            import traceback
            print(f'SMOKE FAIL: {exc}', file=sys.stderr, flush=True)
            traceback.print_exc()
            code = 1
        finally:
            app.close()
            # A non-daemon serial worker owns its resources until its step finishes.
            while not app.destroyed:
                root.update()
                time.sleep(0.005)
        return code
    if args.screenshot:
        def capture():
            try:
                screenshot(root, args.screenshot)
            except Exception as exc:
                app._problem(f'截图失败：{exc}')
        root.after(700, capture)
    root.mainloop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
