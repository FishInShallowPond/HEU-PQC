"""Chat-style text and image UI for the authenticated local channel."""
from __future__ import annotations

import queue
import shutil
import tempfile
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, ttk

from PIL import Image, ImageTk, UnidentifiedImageError

from communication import CommunicationConfig, CommunicationSession
from image_utils import read_clipboard_image, read_image_file, thumbnail, validate_image
from profiles import PROFILES
from text_crypto import (
    MAX_TEXT_BYTES, RECORD_FILE_BEGIN, RECORD_FILE_CHUNK, RECORD_FILE_END,
    TextSecurityError,
)
from ui_widgets import TickCheckbutton

SIG_KEYS = tuple(key for key, profile in PROFILES.items() if profile.family == 'signature')
KEM_KEYS = tuple(key for key, profile in PROFILES.items() if profile.family == 'kem')
CHAT_BG = '#EEF3F6'
BUBBLE_A = '#FFFFFF'
BUBBLE_B = '#DDF3EC'
BORDER = '#D3DEE5'
PACKET_TYPE_NAMES = {
    RECORD_FILE_BEGIN: '文件开始',
    RECORD_FILE_CHUNK: '数据块',
    RECORD_FILE_END: '文件结束',
}


def _masked(value):
    return value[:8] + '…' + value[-8:] if len(value) > 20 else value


def _display_time(value):
    try:
        return datetime.fromisoformat(value).astimezone().strftime('%H:%M:%S')
    except (ValueError, TypeError):
        return '--:--:--'


class CommunicationPanel(ttk.Frame):
    """Combined connection controls, chat transcript and bottom composer."""

    def __init__(self, app, parent):
        super().__init__(parent, padding=(14, 10, 14, 8))
        self.app = app
        self.session = None
        self.busy = False
        self.worker = None
        self.closing = False
        self.shutdown_complete = False
        self.last_export = None
        self._events = queue.Queue()
        self._pending_done = None
        self._poll_id = None
        self._job = None
        self.sender = 'A'
        self.attachment = None
        self.key_data = None
        self.sidebar_width = 340
        self.sidebar_visible = True
        self._sidebar_after_id = None
        self.current_packet = None
        self._packet_record = None
        self.packet_choice_map = {}
        self.buttons = {}
        self.chat_records = []
        self.image_messages = []
        self._photos = []
        self._view_windows = []
        self._attachment_dir = Path(tempfile.mkdtemp(prefix='LC01_chat_'))
        self.signature_var = tk.StringVar(value='dilithium2')
        self.kem_var = tk.StringVar(value='kyber512')
        self.simulate_var = app.simulate_var
        self.port1_var = tk.StringVar(value=app.port1_var.get())
        self.port2_var = tk.StringVar(value=app.port2_var.get())
        self.baudrate_var = tk.StringVar(value=app.baudrate_var.get())
        self.timeout_var = tk.StringVar(value=app.timeout_var.get())
        self.status_var = tk.StringVar(value='未连接。请确认两路串口后连接。')
        self.connection_var = tk.StringVar(value='未连接')
        self.key_reveal_var = tk.BooleanVar(value=False)
        self.attachment_label_var = tk.StringVar(value='')
        self._build()
        self._poll_id = self.after(25, self._poll)
        self._render_key_panel()

    def _build(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky='ew', pady=(0, 8))
        ttk.Label(top, text='安全会话', style='Title.TLabel').pack(side='left')
        ttk.Label(top, text='文本与图片 · 认证加密', style='Muted.TLabel').pack(
            side='left', padx=(12, 0), pady=(8, 0))
        self.connection_badge = tk.Label(
            top, textvariable=self.connection_var, font=('Microsoft YaHei UI', 9, 'bold'),
            padx=12, pady=5, background='#E1E9EE', foreground='#526775')
        self.connection_badge.pack(side='right')
        self.sidebar_toggle_button = ttk.Button(
            top, text='隐藏侧栏', command=self.toggle_sidebar, width=10)
        self.sidebar_toggle_button.pack(side='right', padx=(0, 10))
        self.side_pane = ttk.Panedwindow(self, orient='horizontal')
        self.side_pane.grid(row=1, column=0, sticky='nsew')
        self._build_chat(self.side_pane)
        self._build_sidebar(self.side_pane)
        self.side_pane.add(self.chat_card, weight=4)
        self.side_pane.add(self.side_frame, weight=0)
        self.side_pane.bind('<ButtonRelease-1>', self._remember_sidebar_width)
        self._schedule_sidebar_width()
        ttk.Label(self, textvariable=self.status_var, style='Muted.TLabel',
                  wraplength=1100).grid(row=2, column=0, sticky='ew', pady=(7, 0))

    def _build_chat(self, parent):
        card = tk.Frame(parent, background='white', highlightbackground=BORDER,
                        highlightthickness=1)
        self.chat_card = card
        card.columnconfigure(0, weight=1)
        card.rowconfigure(1, weight=1)
        head = tk.Frame(card, background='white', padx=14, pady=9)
        head.grid(row=0, column=0, sticky='ew')
        tk.Label(head, text='A  ⟷  B', background='white', foreground='#182D3D',
                 font=('Microsoft YaHei UI', 11, 'bold')).pack(side='left')
        clear = tk.Button(head, text='清空聊天', relief='flat', bd=0, background='white',
                          foreground='#7A8B97', font=('Microsoft YaHei UI', 9),
                          command=self.clear_chat)
        clear.pack(side='right', padx=(10, 0))
        self.buttons['clear_chat'] = clear
        tk.Label(head, text='仅显示认证成功的数据', background='white', foreground='#526775',
                 font=('Microsoft YaHei UI', 9)).pack(side='right')
        chat_frame = tk.Frame(card, background=CHAT_BG)
        chat_frame.grid(row=1, column=0, sticky='nsew')
        chat_frame.rowconfigure(0, weight=1)
        chat_frame.columnconfigure(0, weight=1)
        self.chat_canvas = tk.Canvas(chat_frame, background=CHAT_BG, highlightthickness=0)
        self.chat_canvas.grid(row=0, column=0, sticky='nsew')
        scroll = ttk.Scrollbar(chat_frame, orient='vertical', command=self.chat_canvas.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        self.chat_canvas.configure(yscrollcommand=scroll.set)
        self.chat_inner = tk.Frame(self.chat_canvas, background=CHAT_BG)
        self._chat_window = self.chat_canvas.create_window((0, 0), window=self.chat_inner, anchor='nw')
        self.chat_inner.bind('<Configure>', self._chat_configured)
        self.chat_canvas.bind('<Configure>', self._chat_canvas_resized)
        self.chat_canvas.bind('<MouseWheel>', self._chat_scroll)
        self.chat_inner.bind('<MouseWheel>', self._chat_scroll)
        self.empty_chat = tk.Label(
            self.chat_inner, text='连接并建立共享密钥后，可在这里发送文本或图片',
            background=CHAT_BG, foreground='#7A8B97', font=('Microsoft YaHei UI', 10))
        self.empty_chat.pack(pady=80)
        self.attachment_frame = tk.Frame(card, background='#F7FAFB', padx=12, pady=7,
                                         highlightbackground=BORDER, highlightthickness=1)
        self.attachment_frame.grid(row=2, column=0, sticky='ew')
        self.attachment_frame.grid_remove()
        self.attachment_photo_label = tk.Label(self.attachment_frame, background='#F7FAFB')
        self.attachment_photo_label.pack(side='left', padx=(0, 10))
        tk.Label(self.attachment_frame, textvariable=self.attachment_label_var,
                 background='#F7FAFB', foreground='#182D3D',
                 font=('Microsoft YaHei UI', 9)).pack(side='left', fill='x', expand=True)
        remove = tk.Button(self.attachment_frame, text='移除', relief='flat', bd=0,
                           background='#F7FAFB', foreground='#A52A32',
                           command=self.clear_attachment)
        remove.pack(side='right')
        self.buttons['remove_attachment'] = remove
        composer = tk.Frame(card, background='white', padx=12, pady=10)
        self.composer_frame = composer
        composer.grid(row=3, column=0, sticky='ew')
        composer.columnconfigure(1, weight=1)
        identity = tk.Frame(composer, background='white')
        identity.grid(row=0, column=0, sticky='w', padx=(0, 8), pady=(0, 5))
        for role in ('A', 'B'):
            button = tk.Button(identity, text=f'{role}端', width=5, relief='flat', bd=0,
                               font=('Microsoft YaHei UI', 9, 'bold'), padx=7, pady=5,
                               command=lambda r=role: self.select_sender(r))
            button.pack(side='left', padx=(0, 4))
            self.buttons[role] = button
        tools = tk.Frame(composer, background='white')
        tools.grid(row=0, column=1, sticky='e', pady=(0, 5))
        for key, label, callback in (
                ('choose_image', '图片', self.choose_image),
                ('paste_image', '粘贴 Ctrl+V', self.paste_image)):
            button = tk.Button(tools, text=label, relief='flat', bd=0, background='#EDF2F5',
                               foreground='#182D3D', padx=9, pady=4, command=callback)
            button.pack(side='left', padx=(4, 0))
            self.buttons[key] = button
        input_card = tk.Frame(composer, background='#F7FAFB', highlightbackground=BORDER,
                              highlightthickness=1)
        input_card.grid(row=1, column=0, columnspan=2, sticky='ew')
        input_card.columnconfigure(0, weight=1)
        self.message_input = tk.Text(input_card, height=3, width=1, wrap='word', relief='flat', bd=0,
                                     background='#F7FAFB', foreground='#182D3D',
                                     insertbackground='#135C75', font=('Microsoft YaHei UI', 10),
                                     padx=8, pady=7)
        self.message_input.grid(row=0, column=0, sticky='ew')
        self.message_input.bind('<Control-v>', self._paste_event)
        self.message_input.bind('<Control-V>', self._paste_event)
        self.message_input.bind('<Return>', self._return_key)
        footer = tk.Frame(composer, background='white')
        footer.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(7, 0))
        tk.Label(footer, text='Enter发送 · Shift+Enter换行 · Ctrl+V粘贴图片',
                 background='white', foreground='#7A8B97',
                 font=('Microsoft YaHei UI', 8)).pack(side='left')
        self.send_button = ttk.Button(footer, text='发送', command=self.send_current,
                                      style='Primary.TButton', width=10)
        self.send_button.pack(side='right')
        self.buttons['send'] = self.send_button
        self._render_sender_buttons()

    def _build_sidebar(self, parent):
        side = tk.Frame(parent, background='#F7FAFB', width=self.sidebar_width)
        self.side_frame = side
        side.grid_propagate(False)
        side.pack_propagate(False)
        side.columnconfigure(0, weight=1)
        settings = self._card(side, '连接设置')
        settings.pack(fill='x', pady=(0, 9))
        fields = ttk.Frame(settings, style='White.TFrame')
        fields.pack(fill='x')
        fields.columnconfigure(0, weight=1)
        fields.columnconfigure(1, weight=1)
        self.signature_combo = self._field(fields, '签名算法', self.signature_var, 0, 0, SIG_KEYS)
        self.kem_combo = self._field(fields, 'KEM算法', self.kem_var, 0, 1, KEM_KEYS)
        self.port1_combo = self._field(fields, '芯片1串口', self.port1_var, 1, 0, (), normal=True)
        self.port2_combo = self._field(fields, '芯片2串口', self.port2_var, 1, 1, (), normal=True)
        self.baudrate_combo = self._field(fields, '波特率', self.baudrate_var, 2, 0, (), normal=True)
        self.timeout_combo = self._field(fields, '命令超时/秒', self.timeout_var, 2, 1, (), normal=True)
        self.simulate_check = TickCheckbutton(
            fields, text='流程模拟', variable=self.simulate_var,
            background='white')
        self.simulate_check.grid(row=3, column=0, columnspan=2, sticky='w', pady=(4, 2))
        actions = ttk.Frame(settings, style='White.TFrame')
        actions.pack(fill='x', pady=(5, 0))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)
        for key, label, callback, style, row, column, span in (
                ('ports', '刷新串口', self.refresh_ports, 'TButton', 0, 0, 2),
                ('connect', '连接', self.connect, 'Primary.TButton', 1, 0, 1),
                ('disconnect', '结束', self.disconnect, 'TButton', 1, 1, 1),
                ('rekey', '重新建钥', self.rekey, 'TButton', 2, 0, 1),
                ('export', '导出', self.export, 'TButton', 2, 1, 1)):
            button = ttk.Button(actions, text=label, command=callback, style=style)
            button.grid(row=row, column=column, columnspan=span, sticky='ew',
                        padx=(0, 4) if column == 0 else 0, pady=(0, 3))
            self.buttons[key] = button
        self.side_notebook = ttk.Notebook(side)
        self.side_notebook.pack(fill='both', expand=True)
        keys = self._card(self.side_notebook, '当前会话密钥')
        self.key_tab = keys
        self.side_notebook.add(keys, text='会话密钥')
        self.key_text = tk.Text(keys, height=10, width=34, wrap='char', relief='flat', bd=0,
                                background='#F7FAFB', foreground='#182D3D',
                                font=('Consolas', 9), padx=2, pady=2, state='disabled')
        self.key_text.pack(fill='both', expand=True)
        keytools = ttk.Frame(keys, style='White.TFrame')
        keytools.pack(fill='x', pady=(5, 0))
        self.key_reveal_check = TickCheckbutton(
            keytools, text='显示完整密钥', variable=self.key_reveal_var,
            command=self._render_key_panel, background='white')
        self.key_reveal_check.pack(side='left')
        copy_keys = ttk.Button(keytools, text='复制密钥', command=self.copy_keys)
        copy_keys.pack(side='right')
        self.buttons['copy_keys'] = copy_keys
        tk.Label(keys, text='指纹=SHA-256(密钥字节)，用于比较，不是密钥本身。\n仅本机界面显示；通信导出不包含密钥。',
                 background='white', foreground='#7A8B97', wraplength=280,
                 justify='left', font=('Microsoft YaHei UI', 8)).pack(
                     fill='x', pady=(5, 0))
        packet = self._card(self.side_notebook, '密文 / 报文明细')
        self.packet_tab = packet
        self.side_notebook.add(packet, text='密文/报文')
        packet_choice = tk.Frame(packet, background='white')
        packet_choice.pack(fill='x', pady=(0, 5))
        tk.Label(packet_choice, text='查看块', background='white', foreground='#526775',
                 font=('Microsoft YaHei UI', 8)).pack(side='left', padx=(0, 6))
        self.packet_choice_var = tk.StringVar(value='')
        self.packet_selector = ttk.Combobox(
            packet_choice, textvariable=self.packet_choice_var, values=(),
            state='disabled', width=24)
        self.packet_selector.pack(side='left', fill='x', expand=True)
        self.packet_selector.bind('<<ComboboxSelected>>', self._packet_choice_changed)
        packet_body = tk.Frame(packet, background='white')
        packet_body.pack(fill='both', expand=True)
        packet_body.rowconfigure(0, weight=1)
        packet_body.columnconfigure(0, weight=1)
        self.packet_text = tk.Text(
            packet_body, height=10, width=34, wrap='char', relief='flat', bd=0,
            background='#F7FAFB', foreground='#182D3D', font=('Consolas', 9),
            padx=2, pady=2, state='disabled')
        self.packet_text.grid(row=0, column=0, sticky='nsew')
        packet_scroll = ttk.Scrollbar(packet_body, orient='vertical', command=self.packet_text.yview)
        packet_scroll.grid(row=0, column=1, sticky='ns')
        self.packet_text.configure(yscrollcommand=packet_scroll.set)
        packet_actions = ttk.Frame(packet, style='White.TFrame')
        packet_actions.pack(fill='x', pady=(5, 0))
        self.buttons['copy_packet'] = ttk.Button(
            packet_actions, text='复制报文', command=self.copy_packet)
        self.buttons['copy_packet'].pack(side='right')
        tk.Label(packet, text='点击聊天消息下方“报文”查看对应记录。',
                 background='white', foreground='#7A8B97', wraplength=250,
                 justify='left', font=('Microsoft YaHei UI', 8)).pack(
                     fill='x', pady=(5, 0))

    @staticmethod
    def _card(parent, title):
        frame = tk.Frame(parent, background='white', highlightbackground=BORDER,
                         highlightthickness=1, padx=10, pady=8)
        tk.Label(frame, text=title, background='white', foreground='#135C75',
                 font=('Microsoft YaHei UI', 10, 'bold')).pack(anchor='w', pady=(0, 6))
        return frame

    @staticmethod
    def _field(parent, label, variable, row, column, values=(), normal=False):
        frame = ttk.Frame(parent, style='White.TFrame', padding=(0, 0, 5 if column == 0 else 0, 4))
        frame.grid(row=row, column=column, sticky='ew')
        ttk.Label(frame, text=label, style='Muted.TLabel').pack(anchor='w')
        widget = ttk.Combobox(frame, textvariable=variable, values=values,
                              state='normal' if normal else 'readonly', width=13)
        widget.pack(fill='x')
        return widget

    def _render_sender_buttons(self):
        for role, button in (('A', self.buttons['A']), ('B', self.buttons['B'])):
            selected = role == self.sender
            button.configure(background='#135C75' if selected else '#EDF2F5',
                             foreground='white' if selected else '#182D3D')

    def select_sender(self, role):
        if role not in ('A', 'B'):
            raise ValueError('发送端必须是A或B')
        self.sender = role
        self._render_sender_buttons()
        self.message_input.focus_set()

    def on_shown(self):
        if self.sidebar_visible:
            self._schedule_sidebar_width()

    def _schedule_sidebar_width(self):
        if self.shutdown_complete:
            return
        if self._sidebar_after_id is not None:
            try:
                self.after_cancel(self._sidebar_after_id)
            except tk.TclError:
                pass
        self._sidebar_after_id = self.after_idle(self._run_sidebar_width)

    def _run_sidebar_width(self):
        self._sidebar_after_id = None
        self._apply_sidebar_width()

    def _apply_sidebar_width(self):
        if not self.sidebar_visible or not self.side_frame.winfo_exists():
            return
        width = max(280, min(600, int(self.sidebar_width)))
        total = self.side_pane.winfo_width()
        if total > 1:
            self.side_pane.sashpos(0, max(320, total - width))

    def _remember_sidebar_width(self, _event=None):
        if self.sidebar_visible and self.side_frame.winfo_width() > 100:
            self.sidebar_width = self.side_frame.winfo_width()

    def set_sidebar_width(self, width):
        self.sidebar_width = max(280, min(600, int(width)))
        self._apply_sidebar_width()
        return self.sidebar_width

    def toggle_sidebar(self):
        if self.sidebar_visible:
            self._remember_sidebar_width()
            self.side_pane.forget(self.side_frame)
            self.sidebar_visible = False
            self.sidebar_toggle_button.configure(text='显示侧栏')
        else:
            self.side_pane.add(self.side_frame, weight=0)
            self.sidebar_visible = True
            self.sidebar_toggle_button.configure(text='隐藏侧栏')
            self._schedule_sidebar_width()
        return self.sidebar_visible

    def _chat_configured(self, _event=None):
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox('all'))

    def _chat_canvas_resized(self, event):
        self.chat_canvas.itemconfigure(self._chat_window, width=event.width)

    def _chat_scroll(self, event):
        self.chat_canvas.yview_scroll(int(-event.delta / 120), 'units')
        return 'break'

    def _scroll_to_end(self):
        self.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def _new_row(self):
        self.empty_chat.pack_forget()
        row = tk.Frame(self.chat_inner, background=CHAT_BG)
        row.pack(fill='x', padx=12, pady=5)
        return row

    def _append_text_record(self, record):
        row = self._new_row()
        align = 'w' if record['sender'] == 'A' else 'e'
        color = BUBBLE_A if record['sender'] == 'A' else BUBBLE_B
        bubble = tk.Frame(row, background=color, highlightbackground=BORDER,
                          highlightthickness=1, padx=10, pady=7)
        bubble.pack(anchor=align)
        meta = f'{record["sender"]}端 → {record["receiver"]}端   {_display_time(record.get("time"))}'
        tk.Label(bubble, text=meta, background=color, foreground='#64747F',
                 font=('Microsoft YaHei UI', 8)).pack(anchor='w')
        tk.Label(bubble, text=record.get('received_text', ''), background=color,
                 foreground='#182D3D', font=('Microsoft YaHei UI', 10),
                 justify='left', wraplength=560).pack(anchor='w', pady=(3, 0))
        packet_button = tk.Button(
            bubble, text='报文', relief='flat', bd=0, background=color,
            foreground='#135C75', font=('Microsoft YaHei UI', 8),
            command=lambda r=copy_record(record): self._show_packet(r))
        packet_button.pack(anchor='e')
        self.chat_records.append(copy_record(record))
        self._scroll_to_end()

    def _append_image_record(self, record, meta, path):
        row = self._new_row()
        align = 'w' if record['sender'] == 'A' else 'e'
        color = BUBBLE_A if record['sender'] == 'A' else BUBBLE_B
        bubble = tk.Frame(row, background=color, highlightbackground=BORDER,
                          highlightthickness=1, padx=9, pady=7)
        bubble.pack(anchor=align)
        header = f'{record["sender"]}端 → {record["receiver"]}端   {_display_time(record.get("time"))}'
        tk.Label(bubble, text=header, background=color, foreground='#64747F',
                 font=('Microsoft YaHei UI', 8)).pack(anchor='w')
        try:
            preview, size = thumbnail(Path(path).read_bytes(), 300)
            photo = ImageTk.PhotoImage(preview)
            self._photos.append(photo)
            image_label = tk.Label(bubble, image=photo, background=color, cursor='hand2')
            image_label.pack(anchor='w', pady=(4, 4))
            image_label.bind('<Button-1>', lambda _e, p=Path(path): self.view_image(p))
        except (OSError, ValueError, UnidentifiedImageError) as exc:
            tk.Label(bubble, text=f'图片预览失败：{exc}', background=color,
                     foreground='#A52A32', wraplength=520).pack(anchor='w')
        info = (f'{meta["filename"]} · {meta["width"]}×{meta["height"]} · '
                f'{meta["size"] / 1024:.1f} KiB · 已验证')
        tk.Label(bubble, text=info, background=color, foreground='#526775',
                 font=('Microsoft YaHei UI', 8)).pack(anchor='w')
        actions = tk.Frame(bubble, background=color)
        actions.pack(anchor='w', pady=(4, 0))
        for text, callback in (('查看', lambda p=Path(path): self.view_image(p)),
                               ('下载', lambda p=Path(path), n=meta['filename']: self.download_image(p, n)),
                               ('报文', lambda r=copy_record(record): self._show_packet(r))):
            button = tk.Button(actions, text=text, relief='flat', bd=0, background=color,
                               foreground='#135C75', font=('Microsoft YaHei UI', 9),
                               command=callback)
            button.pack(side='left', padx=(0, 12))
        public = copy_record(record)
        public['image_path'] = str(path)
        public['image'] = dict(meta)
        self.chat_records.append(public)
        self.image_messages.append(public)
        self._scroll_to_end()

    def _show_packet(self, record):
        self._packet_record = copy_record(record)
        if record.get('kind') == 'text':
            self.packet_choice_map = {}
            self.packet_selector.configure(values=('完整记录',), state='disabled')
            self.packet_choice_var.set('完整记录')
        else:
            choices = ['传输摘要']
            self.packet_choice_map = {}
            for packet in record.get('packet_details', []):
                packet_type = packet.get('type')
                if packet_type == RECORD_FILE_CHUNK:
                    label = f'数据块 {packet.get("block_index", "?")} · seq {packet.get("sequence", "?")}'
                else:
                    label = f'{PACKET_TYPE_NAMES.get(packet_type, "记录")} · seq {packet.get("sequence", "?")}'
                if label in self.packet_choice_map:
                    label += f' · {len(choices)}'
                self.packet_choice_map[label] = packet
                choices.append(label)
            self.packet_selector.configure(
                values=tuple(choices), state='readonly' if len(choices) > 1 else 'disabled')
            self.packet_choice_var.set(choices[0])
        self._render_packet_text()
        self.side_notebook.select(self.packet_tab)
        if not self.sidebar_visible:
            self.toggle_sidebar()

    def _packet_choice_changed(self, _event=None):
        self._render_packet_text()

    def _render_packet_text(self):
        record = self._packet_record
        if record is None:
            lines = ['当前没有可查看的报文记录']
        else:
            lines = [f'时间: {record.get("time", "-")}',
                     f'类型: {record.get("kind", "-")}',
                     f'{record.get("sender", "-")} → {record.get("receiver", "-")}',
                     f'状态: {record.get("message", "-")}']
            if record.get('kind') == 'text':
                lines += ['', 'Nonce: ' + record.get('nonce_hex', '-'),
                          'AAD/报文头: ' + record.get('header_hex', '-'),
                          '密文: ' + (record.get('ciphertext_hex') or '（空明文）'),
                          '认证标签: ' + record.get('tag_hex', '-'),
                          '原始报文: ' + record.get('original_packet_hex', '-'),
                          '实际交付: ' + record.get('delivered_packet_hex', '-')]
            else:
                lines += ['', '文件: ' + record.get('file_name', '-'),
                          f'大小: {record.get("file_size", 0):,} B',
                          'SHA-256: ' + record.get('sha256', '-'),
                          f'块数: {record.get("chunk_count", 0)}']
                selected = self.packet_choice_map.get(self.packet_choice_var.get())
                if selected is not None:
                    header = selected.get('header_hex', '')
                    ciphertext = selected.get('ciphertext_hex', '')
                    tag = selected.get('tag_hex', '')
                    original = header + ciphertext + tag
                    delivered = selected.get('delivered_packet_hex', original)
                    packet_type = selected.get('type')
                    lines += ['', f'记录: {PACKET_TYPE_NAMES.get(packet_type, packet_type)}',
                              f'序号: {selected.get("sequence", "-")}',
                              'Nonce: ' + selected.get('nonce_hex', '-'),
                              'AAD/报文头: ' + header,
                              '密文: ' + (ciphertext or '（空明文）'),
                              '认证标签: ' + tag,
                              '原始报文: ' + original,
                              '实际交付: ' + delivered]
                else:
                    lines += ['', '记录清单：']
                    for index, packet in enumerate(record.get('packet_summaries', [])):
                        lines.append(
                            f'{index}: {PACKET_TYPE_NAMES.get(packet.get("type"), packet.get("type"))} '
                            f'seq={packet.get("sequence")} '
                            f'encrypted={packet.get("encrypted_bytes")}B')
                    lines.append('\n从上方“查看块”选择一条记录，可查看完整 Nonce、密文、标签和报文 HEX。')
        self.current_packet = '\n'.join(lines)
        self.packet_text.configure(state='normal')
        self.packet_text.delete('1.0', 'end')
        self.packet_text.insert('1.0', self.current_packet)
        self.packet_text.configure(state='disabled')

    def copy_packet(self):
        if not self.current_packet:
            self.status_var.set('当前没有可复制的报文明细')
            return
        self.clipboard_clear()
        self.clipboard_append(self.current_packet)
        self.status_var.set('当前报文明细已复制')

    def clear_chat(self):
        for widget in self.chat_inner.winfo_children():
            widget.destroy()
        self.empty_chat = tk.Label(
            self.chat_inner, text='聊天窗口已清空，可以继续发送文本或图片',
            background=CHAT_BG, foreground='#7A8B97', font=('Microsoft YaHei UI', 10))
        self.empty_chat.pack(pady=80)
        self.chat_records.clear()
        self.image_messages.clear()
        self._photos.clear()
        self.current_packet = None
        self._packet_record = None
        self.packet_choice_map = {}
        self.packet_choice_var.set('')
        self.packet_selector.configure(values=(), state='disabled')
        self.packet_text.configure(state='normal')
        self.packet_text.delete('1.0', 'end')
        self.packet_text.configure(state='disabled')
        for window in list(self._view_windows):
            try:
                self._close_view(window)
            except tk.TclError:
                pass
        shutil.rmtree(self._attachment_dir, ignore_errors=True)
        self._attachment_dir.mkdir(parents=True, exist_ok=True)
        self.status_var.set('聊天窗口已清空；底层加密审计记录仍保留，可继续导出')
        self.refresh_controls()

    def _persist_attachment(self, data, meta):
        self._attachment_dir.mkdir(parents=True, exist_ok=True)
        base = Path(meta['filename'])
        destination = self._attachment_dir / base.name
        index = 1
        while destination.exists():
            destination = self._attachment_dir / f'{base.stem}({index}){base.suffix}'
            index += 1
        destination.write_bytes(data)
        return destination

    def set_attachment(self, data, meta):
        if self.busy or self.session is None or not self.session.ready:
            return False
        self.attachment = (bytes(data), dict(meta))
        self.attachment_label_var.set(
            f'{meta["filename"]}\n{meta["width"]}×{meta["height"]} · {len(data) / 1024:.1f} KiB')
        try:
            preview, _ = thumbnail(data, (88, 66))
            self.attachment_photo = ImageTk.PhotoImage(preview)
            self.attachment_photo_label.configure(image=self.attachment_photo)
        except (ValueError, UnidentifiedImageError) as exc:
            self.attachment = None
            self.status_var.set(f'无法生成附件预览：{exc}')
            return False
        self.attachment_frame.grid()
        self.status_var.set('图片已附加；点击“发送”后执行认证加密传输')
        self.refresh_controls()
        return True

    def clear_attachment(self):
        self.attachment = None
        self.attachment_photo = None
        self.attachment_photo_label.configure(image='')
        self.attachment_label_var.set('')
        self.attachment_frame.grid_remove()
        self.refresh_controls()

    def choose_image(self):
        if self.busy or self.session is None or not self.session.ready:
            return False
        path = filedialog.askopenfilename(
            parent=self, title='选择图片',
            filetypes=(('图片', '*.png *.jpg *.jpeg *.webp'), ('全部文件', '*.*')))
        if not path:
            return False
        return self.attach_image_path(path)

    def attach_image_path(self, path):
        try:
            data, meta = read_image_file(path)
            return self.set_attachment(data, meta)
        except (OSError, ValueError) as exc:
            self.status_var.set(f'图片不可用：{exc}')
            return False

    def paste_image(self):
        if self.busy or self.session is None or not self.session.ready:
            return False
        try:
            value = read_clipboard_image()
        except (OSError, ValueError) as exc:
            self.status_var.set(f'读取剪贴板图片失败：{exc}')
            return False
        if value is None:
            self.status_var.set('剪贴板中没有可用的图片；文本可直接粘贴到输入框')
            return False
        data, meta = value
        return self.set_attachment(data, meta)

    def _paste_event(self, _event=None):
        if self.busy or self.session is None or not self.session.ready:
            return None
        try:
            value = read_clipboard_image()
        except (OSError, ValueError):
            return None
        if value is not None and self.set_attachment(*value):
            return 'break'
        return None

    def _return_key(self, event):
        if event.state & 0x0001:
            self.message_input.insert('insert', '\n')
            return 'break'
        self.send_current()
        return 'break'

    def _config(self):
        try:
            baud = int(self.baudrate_var.get())
            command_timeout = float(self.timeout_var.get())
        except ValueError as exc:
            raise ValueError('波特率和命令超时必须是有效数值') from exc
        return CommunicationConfig(
            self.signature_var.get(), self.kem_var.get(),
            self.port1_var.get().strip(), self.port2_var.get().strip(),
            baud, 0.2, command_timeout, 0.08, bool(self.simulate_var.get())).validate()

    def refresh_ports(self):
        if self.busy or self.closing or self.shutdown_complete or self.app.busy or self.session is not None:
            return []
        try:
            from serial.tools import list_ports
            ports = sorted({port.device for port in list_ports.comports()})
        except Exception as exc:
            self.status_var.set(f'串口枚举失败：{exc}')
            return []
        for combo in (self.port1_combo, self.port2_combo):
            combo.configure(values=ports)
        if ports:
            if self.port1_var.get().strip() not in ports:
                self.port1_var.set(ports[0])
            if self.port2_var.get().strip() not in ports:
                self.port2_var.set(ports[1] if len(ports) > 1 else ports[0])
            self.status_var.set('可用串口：' + '、'.join(ports))
        else:
            self.status_var.set('未发现串口；仍可手动填写COM端口')
        return ports

    def _start_work(self, kind, work):
        if (self.busy or self.closing or self.shutdown_complete or self.app.busy
                or self.app.session is not None):
            return False
        self.busy = True
        self._job = kind
        self._pending_done = None
        self.app._update_controls()
        self.refresh_controls()
        def worker():
            outcome = {'kind': kind, 'error': None, 'result': None}
            try:
                outcome['result'] = work()
            except Exception as exc:
                outcome['error'] = str(exc)
            finally:
                self._events.put(('_done', outcome))
        self.worker = threading.Thread(target=worker, name=f'LC01-comm-{kind}', daemon=False)
        self.worker.start()
        return True

    def connect(self):
        if self.busy or self.closing or self.app.busy or self.app.session is not None:
            return
        if self.session is not None and not self.session.closed:
            self.status_var.set('当前通信仍在进行；请先结束通信。')
            return
        try:
            config = self._config()
        except ValueError as exc:
            self.status_var.set(str(exc))
            return
        self.key_data = None
        self._render_key_panel()
        self.status_var.set('正在建立安全会话…')
        def work():
            session = CommunicationSession(config, emit=self._emit)
            self._events.put(('_session', session))
            session.connect()
            return session
        self._start_work('connect', work)

    def rekey(self):
        if self.busy or self.closing or self.session is None or self.session.closed:
            return
        self.key_data = None
        self._render_key_panel()
        self.status_var.set('正在重新建立共享密钥…')
        self._start_work('rekey', self.session.rekey)

    def _emit(self, event):
        self._events.put(('session', event))

    def send_current(self):
        if self.busy or self.closing or self.session is None or not self.session.ready:
            return
        sender = self.sender
        if self.attachment is not None:
            data, meta = self.attachment
            self.status_var.set('正在认证加密并发送图片…')
            def work():
                record = self.session.send_file(sender, meta['filename'], meta['mime'], data)
                if not record.get('ok'):
                    return record, None, None
                received = self.session.payload(record['payload_id'])
                verified_meta = validate_image(received, record['file_name'])
                path = self._persist_attachment(received, verified_meta)
                self.session.release_payload(record['payload_id'])
                return record, verified_meta, path
            self._start_work('send_image', work)
            return
        text_value = self.message_input.get('1.0', 'end-1c')
        if not text_value:
            self.status_var.set('请输入文本或附加图片')
            return
        plaintext_size = len(text_value.encode('utf-8'))
        if plaintext_size > MAX_TEXT_BYTES:
            self.status_var.set(f'文本编码后超过{MAX_TEXT_BYTES}字节')
            return
        self.status_var.set('正在认证加密并发送文本…')
        def work_text():
            return self.session.send(sender, text_value)
        self._start_work('send_text', work_text)

    def send_text(self, role):
        self.select_sender(role)
        self.send_current()

    def refresh_keys(self):
        if self.session is None or not self.session.ready:
            self.key_data = None
        else:
            try:
                self.key_data = self.session.key_material()
            except (RuntimeError, TextSecurityError):
                self.key_data = None
        self._render_key_panel()

    def _render_key_panel(self):
        if self.key_data is None:
            value = '当前没有已确认的会话密钥'
        else:
            reveal = bool(self.key_reveal_var.get())
            def shown(name, fingerprint):
                full = self.key_data[name]
                return f'{full}\n指纹 {fingerprint}' if reveal else f'{_masked(full)}\n指纹 {fingerprint}'
            value = '\n'.join((
                f'双向确认: {"通过" if self.key_data["both_directions_confirmed"] else "失败"}',
                f'会话ID: {self.key_data["session_id_hex"]}',
                '',
                '共享密钥 K(A端):', shown('k_a_hex', self.key_data['k_a_fingerprint']),
                '共享密钥 K(B端):', shown('k_b_hex', self.key_data['k_b_fingerprint']),
                'AES-256-GCM A→B:', shown('a_to_b_aes_hex', self.key_data['a_to_b_aes_fingerprint']),
                'AES-256-GCM B→A:', shown('b_to_a_aes_hex', self.key_data['b_to_a_aes_fingerprint']),
                '', '完整密钥仅本地显示，不写入通信导出。'))
        self.key_text.configure(state='normal')
        self.key_text.delete('1.0', 'end')
        self.key_text.insert('1.0', value)
        self.key_text.configure(state='disabled')

    def copy_keys(self):
        if self.key_data is None:
            self.status_var.set('当前没有可复制的会话密钥')
            return
        if not self.key_reveal_var.get():
            self.status_var.set('请先勾选“显示完整密钥”，再复制')
            return
        value = (f'K(A端)={self.key_data["k_a_hex"]}\nK(B端)={self.key_data["k_b_hex"]}\n'
                 f'AES(A→B)={self.key_data["a_to_b_aes_hex"]}\n'
                 f'AES(B→A)={self.key_data["b_to_a_aes_hex"]}\n'
                 f'Session={self.key_data["session_id_hex"]}')
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set('已复制当前会话密钥；请勿在不可信环境传播')

    def view_image(self, path):
        path = Path(path)
        try:
            with Image.open(path) as source:
                source.load()
                preview = source.convert('RGBA')
                preview.thumbnail((900, 700), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(preview)
        except (OSError, ValueError, UnidentifiedImageError) as exc:
            self.status_var.set(f'无法查看图片：{exc}')
            return None
        window = tk.Toplevel(self)
        window.title(path.name)
        window.configure(background='#182D3D')
        label = tk.Label(window, image=photo, background='#182D3D')
        label.image = photo
        label.pack(fill='both', expand=True, padx=10, pady=10)
        actions = tk.Frame(window, background='#182D3D')
        actions.pack(fill='x', pady=(0, 10), padx=10)
        ttk.Button(actions, text='另存为…', command=lambda: self.download_image(path, path.name)).pack(side='right')
        ttk.Button(actions, text='关闭', command=window.destroy).pack(side='right', padx=(0, 7))
        self._view_windows.append(window)
        window.protocol('WM_DELETE_WINDOW', lambda w=window: self._close_view(w))
        return window

    def _close_view(self, window):
        if window in self._view_windows:
            self._view_windows.remove(window)
        window.destroy()

    def download_image(self, source, suggested):
        destination = filedialog.asksaveasfilename(
            parent=self, title='下载图片', initialfile=suggested,
            filetypes=(('图片', '*.png *.jpg *.jpeg *.webp'), ('全部文件', '*.*')))
        if not destination:
            return False
        try:
            shutil.copyfile(source, destination)
            self.status_var.set(f'图片已保存：{destination}')
            return True
        except OSError as exc:
            self.status_var.set(f'保存图片失败：{exc}')
            return False

    def export(self, directory=None):
        if self.busy or self.closing or self.session is None:
            return
        if directory is None:
            directory = filedialog.askdirectory(parent=self, title='选择通信记录导出目录')
        if not directory:
            return
        try:
            self.last_export = self.session.export(directory)
            self.status_var.set(f'通信记录已导出：{self.last_export}')
        except Exception as exc:
            self.status_var.set(f'导出失败：{exc}')

    def disconnect(self):
        if self.busy:
            return
        if self.session is not None:
            self.session.close()
        self.key_data = None
        self.clear_attachment()
        self._render_key_panel()
        self.connection_var.set('已结束')
        self.connection_badge.configure(background='#E1E9EE', foreground='#526775')
        self.status_var.set('通信已结束 · 聊天记录保留在窗口中')
        self.refresh_controls()

    def _handle_session_event(self, event):
        if event.get('type') == 'log':
            self.app._log(event['message'])
        elif event.get('type') == 'status':
            self.status_var.set(event.get('message', ''))

    def _finish(self, outcome):
        self.busy = False
        self.worker = None
        self._job = None
        kind, error = outcome['kind'], outcome['error']
        result = outcome.get('result')
        self.app._update_controls()
        if kind in ('connect', 'rekey'):
            if error:
                self.status_var.set(f'会话建立失败：{error}')
                self.key_data = None
                self.connection_var.set('未连接')
                self.connection_badge.configure(background='#FBEAEC', foreground='#A52A32')
            else:
                self.refresh_keys()
                self.connection_var.set('已连接')
                self.connection_badge.configure(background='#E6F3EB', foreground='#176443')
                self.status_var.set('安全会话已建立 · 芯片1签名已由芯片2验签 · 密钥确认通过')
        elif kind == 'send_text':
            if error:
                self.status_var.set(f'文本发送失败：{error}')
            else:
                self._append_text_record(result)
                self.message_input.delete('1.0', 'end')
                self.status_var.set('文本已通过认证解密并交付')
        elif kind == 'send_image':
            if error:
                self.status_var.set(f'图片发送失败：{error}')
            else:
                record, meta, path = result
                if record.get('ok'):
                    self._append_image_record(record, meta, path)
                    self.clear_attachment()
                    self.status_var.set('图片已认证解密并通过SHA-256校验')
                else:
                    self.status_var.set(f'图片发送失败：{record.get("message", "未知错误")}')
        if self.session is not None and self.session.ready:
            self.refresh_keys()
        else:
            self.key_data = None
            self._render_key_panel()
        if self.closing:
            self._finalize_close()
        else:
            self.refresh_controls()
            if self.app.closing:
                self.app._maybe_destroy()

    def _poll(self):
        self._poll_id = None
        while True:
            try:
                kind, value = self._events.get_nowait()
            except queue.Empty:
                break
            if kind == 'session':
                self._handle_session_event(value)
            elif kind == '_session':
                self.session = value
            elif kind == '_done':
                self._pending_done = value
        if self._pending_done is not None and (self.worker is None or not self.worker.is_alive()):
            outcome, self._pending_done = self._pending_done, None
            self._finish(outcome)
        if not self.shutdown_complete:
            self._poll_id = self.after(25, self._poll)

    def refresh_controls(self):
        if self.shutdown_complete:
            return
        usable = not self.busy and not self.closing and not self.app.busy and not self.app.session
        active = self.session is not None and not self.session.closed
        ready = usable and self.session is not None and self.session.ready
        self.buttons['ports'].configure(state='normal' if usable and not active else 'disabled')
        self.buttons['connect'].configure(state='normal' if usable and not active else 'disabled')
        self.buttons['rekey'].configure(state='normal' if usable and active else 'disabled')
        self.buttons['disconnect'].configure(state='normal' if usable and active else 'disabled')
        self.buttons['export'].configure(state='normal' if usable and self.session is not None else 'disabled')
        for key in ('choose_image', 'paste_image', 'send', 'A', 'B'):
            self.buttons[key].configure(state='normal' if ready else 'disabled')
        self.message_input.configure(state='normal' if ready else 'disabled')
        self.key_reveal_check.configure(state='normal' if self.key_data is not None and usable else 'disabled')
        self.buttons['copy_keys'].configure(state='normal' if self.key_data is not None and usable else 'disabled')
        for widget in (self.signature_combo, self.kem_combo, self.port1_combo, self.port2_combo,
                       self.baudrate_combo, self.timeout_combo):
            widget.configure(state='disabled' if not usable or active else
                             ('readonly' if widget in (self.signature_combo, self.kem_combo) else 'normal'))
        self.simulate_check.configure(state='normal' if usable and not active else 'disabled')

    def close(self):
        if self.shutdown_complete:
            return
        self.closing = True
        if self.session is not None:
            self.session.stop()
        if self.busy or self.worker is not None:
            self.refresh_controls()
            return
        self._finalize_close()

    def _finalize_close(self):
        if self.shutdown_complete:
            return
        if self.session is not None:
            self.session.close()
            self.session = None
        self.key_data = None
        self.busy = False
        self.worker = None
        for window in list(self._view_windows):
            try:
                window.destroy()
            except tk.TclError:
                pass
        self._view_windows.clear()
        shutil.rmtree(self._attachment_dir, ignore_errors=True)
        if self._poll_id is not None:
            try:
                self.after_cancel(self._poll_id)
            except Exception:
                pass
            self._poll_id = None
        self.shutdown_complete = True
        if self._sidebar_after_id is not None:
            try:
                self.after_cancel(self._sidebar_after_id)
            except tk.TclError:
                pass
            self._sidebar_after_id = None
        self.app._maybe_destroy()


def copy_record(record):
    return {key: value for key, value in record.items()}
