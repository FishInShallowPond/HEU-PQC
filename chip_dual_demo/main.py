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
    x, y = root.winfo_rootx(), root.winfo_rooty()
    bounds = (x, y, x + root.winfo_width(), y + root.winfo_height())
    if sys.platform == 'win32':
        # Tk coordinates are virtualized at 150%/200% desktop scaling.
        # DWM supplies physical pixels, which Pillow's screen capture uses.
        import ctypes
        from ctypes import wintypes
        rect = wintypes.RECT()
        window = ctypes.windll.user32.GetParent(root.winfo_id())
        status = ctypes.windll.dwmapi.DwmGetWindowAttribute(window, 9, ctypes.byref(rect), ctypes.sizeof(rect))
        if status == 0:
            bounds = (rect.left, rect.top, rect.right, rect.bottom)
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
            screenshot(root, screenshot_path)
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
    print('SMOKE PASS: real Tk events, original/received fields, tamper continuation and session cleanup', flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description='LC01 双芯片桌面演示')
    parser.add_argument('--simulate', action='store_true', help='显式启用流程模拟，不连接硬件')
    parser.add_argument('--smoke-test', action='store_true', help='隐藏窗口运行 KEM 与签名 GUI 模拟测试，成功返回0')
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
