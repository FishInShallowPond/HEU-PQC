"""Modal normal-order transfer preview and equal-length fault injection editor."""
from __future__ import annotations

import re
import tkinter as tk
from tkinter import ttk

from workflow import diff_offsets


class TransferEditor:
    """Test API: select_field, apply, reset, flip_byte, continue_run, close.

    Inspect field_var, original_text, edit_text, offset_var, mask_var,
    changed_offsets, diff_var, error_var, editable and buttons.
    """

    def __init__(self, app):
        self.app = app
        self.session = app.session
        self.window = tk.Toplevel(app.root)
        self.window.title('发送数据篡改 / 对比')
        self.window.geometry('1080x690')
        self.window.minsize(900, 580)
        self.window.configure(background='#F3F6F8')
        self.window.transient(app.root)
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        self.window.bind('<Escape>', lambda _: self.close())
        self.field_var = tk.StringVar()
        self.offset_var = tk.StringVar(value='0')
        self.mask_var = tk.StringVar(value='01')
        self.diff_var = tk.StringVar()
        self.error_var = tk.StringVar()
        self.state_var = tk.StringVar()
        self.route_var = tk.StringVar()
        self.right_title_var = tk.StringVar()
        self.changed_offsets = []
        self.editable = False
        self.original = b''
        self.current_name = None
        self.closed = False
        self._preview_valid = False
        self._build()
        family = self.session.profile.family
        self.field_combo.configure(values=('pk', 'ct') if family == 'kem' else ('pk', 'signature', 'message'))
        candidates = ('ct', 'signature', 'message', 'pk')
        current = next((name for name in candidates if name in self.session.editable_transfers), 'pk')
        self.select_field(current)
        self.window.update_idletasks()
        self.window.grab_set()
        self.window.lift()
        self.edit_text.focus_set()

    def _build(self):
        outer = ttk.Frame(self.window, padding=18)
        outer.pack(fill='both', expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(3, weight=1)
        top = ttk.Frame(outer)
        top.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        ttk.Label(top, text='发送数据篡改 / 对比', style='Section.TLabel').pack(side='left')
        self.field_combo = ttk.Combobox(top, width=14, state='readonly', textvariable=self.field_var)
        self.field_combo.pack(side='left', padx=18)
        self.field_combo.bind('<<ComboboxSelected>>', lambda _: self.select_field(self.field_var.get()))
        ttk.Label(top, textvariable=self.route_var).pack(side='left')
        ttk.Label(outer, textvariable=self.state_var, wraplength=1000,
                  style='Muted.TLabel').grid(row=1, column=0, sticky='ew', pady=(0, 8))
        tools = ttk.Frame(outer)
        tools.grid(row=2, column=0, sticky='ew', pady=(0, 12))
        ttk.Label(tools, text='字节偏移（从 0 开始）').pack(side='left')
        self.offset_entry = ttk.Entry(tools, textvariable=self.offset_var, width=11)
        self.offset_entry.pack(side='left', padx=(8, 16))
        ttk.Label(tools, text='XOR mask / HEX').pack(side='left')
        self.mask_entry = ttk.Entry(tools, textvariable=self.mask_var, width=7)
        self.mask_entry.pack(side='left', padx=8)
        self.buttons = {}
        self.buttons['flip'] = ttk.Button(tools, text='翻转字节', command=self.flip_byte)
        self.buttons['flip'].pack(side='left', padx=(0, 12))
        ttk.Label(tools, text='偏移支持十进制或 0x；mask 为 00..FF', style='Muted.TLabel').pack(side='left')
        columns = ttk.Frame(outer)
        columns.grid(row=3, column=0, sticky='nsew')
        columns.columnconfigure(0, weight=1, uniform='hex')
        columns.columnconfigure(1, weight=1, uniform='hex')
        columns.rowconfigure(1, weight=1)
        ttk.Label(columns, text='原始输出 / 原始消息', style='Section.TLabel').grid(row=0, column=0, sticky='w', pady=(0, 6))
        ttk.Label(columns, textvariable=self.right_title_var, style='Section.TLabel').grid(row=0, column=1, sticky='w', padx=(12, 0), pady=(0, 6))
        self.original_text = self._hex_panel(columns, 0)
        self.edit_text = self._hex_panel(columns, 1)
        self.edit_text.bind('<<Modified>>', self._modified)
        ttk.Label(outer, textvariable=self.diff_var, wraplength=1000).grid(row=4, column=0, sticky='ew', pady=(10, 4))
        tk.Label(outer, textvariable=self.error_var, foreground='#A52A32', background='#F3F6F8',
                 font=('Microsoft YaHei UI', 10), anchor='w', justify='left', wraplength=1000).grid(
                     row=5, column=0, sticky='ew', pady=(0, 8))
        bottom = ttk.Frame(outer)
        bottom.grid(row=6, column=0, sticky='ew')
        for key, text, command in (
            ('apply', '应用发送副本', self.apply), ('reset', '恢复原值', self.reset),
            ('continue', '应用并继续执行', self.continue_run), ('close', '关闭', self.close),
        ):
            self.buttons[key] = ttk.Button(bottom, text=text, command=command)
            self.buttons[key].pack(side='left', padx=(0, 9))
        ttk.Label(outer, text='编辑不会发送；应用仅保存等长副本。继续后由芯片实际计算，原始输出与已发送历史保持不变。',
                  style='Muted.TLabel', wraplength=1000).grid(row=7, column=0, sticky='ew', pady=(10, 0))

    def _hex_panel(self, parent, column):
        frame = ttk.Frame(parent, padding=(6, 0, 0, 0) if column else (0, 0, 6, 0))
        frame.grid(row=1, column=column, sticky='nsew')
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        text = tk.Text(frame, wrap='char', width=30, height=10, font=('Consolas', 11),
                       relief='solid', borderwidth=1, background='white', foreground='#182D3D',
                       selectbackground='#CDE6F1', insertbackground='#135C75', undo=True, padx=9, pady=9)
        text.grid(row=0, column=0, sticky='nsew')
        scroll = ttk.Scrollbar(frame, orient='vertical', command=text.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        text.configure(yscrollcommand=scroll.set)
        text.tag_configure('diff', foreground='#A52A32', background='#FFE0E3')
        text.bind('<Control-a>', self._select_all)
        text.bind('<Control-A>', self._select_all)
        return text

    @staticmethod
    def _select_all(event):
        event.widget.tag_add('sel', '1.0', 'end-1c')
        return 'break'

    def select_field(self, name):
        if name not in ('pk', 'ct', 'signature', 'message'):
            raise ValueError('未知传输字段')
        self.current_name = name
        self.field_var.set(name)
        self.original = bytes(self.session.fields.get(name, b''))
        received = self.session.fields.get('received_' + name)
        available = name in self.session.pending_transfers or name in self.session.fields
        self.editable = (available and received is None and name in self.session.editable_transfers
                         and not self.app._failed and self.session.result is None)
        data = received if received is not None else self.session.pending_transfers.get(name, self.original)
        self.route_var.set('芯片2输出 → 芯片1输入' if name == 'ct' else '芯片1输出 → 芯片2输入')
        self.right_title_var.set('接收/输入（已获响应）' if received is not None else '发送副本 / 正常序 HEX')
        self.state_var.set('可编辑：红色为与原始数据不同的字节；原始芯片输出不变。' if self.editable else
                           ('只读：已获有效响应的实际发送输入，非硬件读回；不能修改历史。' if received is not None else
                            '只读：当前步骤尚不能修改此字段，或数据尚未生成。'))
        self._replace(self.original_text, self.original.hex().upper(), editable=False)
        self._replace(self.edit_text, bytes(data).hex().upper(), editable=self.editable)
        for widget in (self.offset_entry, self.mask_entry):
            widget.configure(state='normal' if self.editable else 'disabled')
        for key in ('flip', 'reset'):
            self.buttons[key].configure(state='normal' if self.editable else 'disabled')
        can_continue = self.session.result is None and not self.app._failed
        self.buttons['continue'].configure(state='normal' if can_continue else 'disabled',
                                           text='应用并继续执行' if self.editable else '继续执行')
        self.error_var.set('')
        self.update_preview()

    @staticmethod
    def _replace(widget, text, editable):
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', text)
        widget.edit_modified(False)
        widget.configure(state='normal' if editable else 'disabled')

    def _draft(self):
        try:
            data = bytes.fromhex(self.edit_text.get('1.0', 'end-1c'))
        except ValueError as exc:
            raise ValueError('HEX 无效：每字节须有两个十六进制字符，可含空白。原始数据未改变。') from exc
        if len(data) != len(self.original):
            raise ValueError(f'须保持等长 {len(self.original)} B；当前 {len(data)} B。原始数据未改变。')
        return data

    def _modified(self, _event=None):
        if self.edit_text.edit_modified():
            self.edit_text.edit_modified(False)
            self.update_preview()

    @staticmethod
    def _mark(widget, offsets):
        text = widget.get('1.0', 'end-1c')
        positions = [match.start() for match in re.finditer(r'[0-9a-fA-F]', text)]
        widget.tag_remove('diff', '1.0', 'end')
        for offset in offsets:
            for nibble in (offset * 2, offset * 2 + 1):
                if nibble < len(positions):
                    pos = positions[nibble]
                    widget.tag_add('diff', f'1.0+{pos}c', f'1.0+{pos + 1}c')

    def update_preview(self):
        self._preview_valid = False
        try:
            data = self._draft()
            self.changed_offsets = list(diff_offsets(self.original, data))
            self._mark(self.original_text, self.changed_offsets)
            self._mark(self.edit_text, self.changed_offsets)
            offsets = ', '.join(str(i) for i in self.changed_offsets[:48]) or '无'
            if len(self.changed_offsets) > 48:
                offsets += f' …（另 {len(self.changed_offsets) - 48} 个）'
            self.diff_var.set(f'{len(data):,} B · 不同字节 {len(self.changed_offsets)} 个 · offset（从 0 开始）：{offsets}')
            self.error_var.set('')
            self._preview_valid = True
        except ValueError as exc:
            self.changed_offsets = []
            for widget in (self.original_text, self.edit_text):
                widget.tag_remove('diff', '1.0', 'end')
            self.diff_var.set('请修正 HEX；尚未应用或发送。')
            self.error_var.set(str(exc))
        self.buttons['apply'].configure(state='normal' if self.editable and self._preview_valid else 'disabled')

    def flip_byte(self):
        if not self.editable:
            return False
        try:
            text = self.offset_var.get().strip()
            offset = int(text, 16 if text.lower().startswith('0x') else 10)
            mask = int(self.mask_var.get().strip(), 16)
            data = bytearray(self._draft())
            if not 0 <= offset < len(data):
                raise ValueError(f'偏移超出范围；应为 0..{len(data) - 1}。')
            if not 0 <= mask <= 255:
                raise ValueError('XOR mask 须为一个字节：00..FF。')
            data[offset] ^= mask
            self._replace(self.edit_text, data.hex().upper(), editable=True)
            self.update_preview()
            self.edit_text.see(f'1.0+{offset * 2}c')
            return True
        except ValueError as exc:
            self.error_var.set(f'未翻转：{exc}')
            return False

    def apply(self):
        if not self.editable:
            return False
        try:
            data = self._draft()
            self.session.set_transfer(self.current_name, data)
            self.update_preview()
            self.state_var.set('已应用发送副本，尚未发送；可继续修改，或继续执行芯片计算。')
            return True
        except (ValueError, RuntimeError) as exc:
            self.error_var.set(f'未应用：{exc}')
            return False

    def reset(self):
        if not self.editable:
            return False
        try:
            self.session.reset_transfer(self.current_name)
            self.select_field(self.current_name)
            self.state_var.set('发送副本已恢复原值，尚未发送。')
            return True
        except (ValueError, RuntimeError) as exc:
            self.error_var.set(str(exc))
            return False

    def continue_run(self):
        if self.session.result is not None or self.app._failed:
            return False
        if self.editable and not self.apply():
            return False
        self.close()
        self.app.start_run()
        return True

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.window.grab_release()
        self.window.destroy()
        if self.app.transfer_editor is self:
            self.app.transfer_editor = None
        self.app._update_controls()
