"""Tk desktop operator for the dual LC01 session; Tk is main-thread only."""
from __future__ import annotations

import math
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from profiles import PROFILES
from ui_widgets import TickCheckbutton
from workflow import COMPARISON_PAIRS, DemoConfig, DemoSession, diff_offsets


BG = '#F3F6F8'
INK = '#182D3D'
MUTED = '#526775'
ACCENT = '#135C75'
GREEN = '#176443'
RED = '#A52A32'
AMBER = '#805000'
FONT = ('Microsoft YaHei UI', 10)
MONO = ('Consolas', 11)
FIELD_NAMES = {
    'pk': '公钥 PK', 'sk': '私钥 SK', 'ct': '密文 CT',
    'k1': '密钥 K1', 'k2': '密钥 K2', 'message': '消息',
    'signature': '签名', 'verify_response': '验签响应',
    'received_pk': '公钥输入', 'received_ct': '密文输入',
    'received_signature': '签名输入', 'received_message': '消息输入',
}
COMPARE_PAIRS = COMPARISON_PAIRS


class DemoApp:
    """Public inspection: session, fields, field_widgets, result, busy, events_seen."""

    def __init__(self, root: tk.Tk, simulate: bool = False):
        self.root = root
        self.session = None
        self.worker = None
        self.busy = False
        self.closing = False
        self.destroyed = False
        self.fields = {}
        self.field_widgets = {}
        self.field_lengths = {}
        self.copy_buttons = {}
        self.field_tabs = {}
        self.transfer_editor = None
        self.communication_panel = None
        self._current_mode = 'demo'
        self.pause_message = ''
        self.tampered = False
        self.result = None
        self.steps = []
        self.step_states = {}
        self.events_seen = {'log': 0, 'field': 0, 'step': 0, 'result': 0, 'pause': 0, 'transfer': 0}
        self.last_error = ''
        self.last_export = None
        self._failed = False
        self._events = queue.Queue()
        self._pending_done = None
        self._stop_requested = threading.Event()
        self._config_widgets = []
        self._profile_keys = list(PROFILES)
        self._profile_labels = [
            f'{p.name}  /  {"密钥封装 KEM" if p.family == "kem" else "数字签名"}'
            for p in PROFILES.values()
        ]
        default = 'kyber512' if 'kyber512' in PROFILES else self._profile_keys[0]
        self.algorithm_var = tk.StringVar(value=self._profile_labels[self._profile_keys.index(default)])
        self.simulate_var = tk.BooleanVar(value=simulate)
        self.pause_transfer_var = tk.BooleanVar(value=False)
        self.port1_var = tk.StringVar(value='COM5')
        self.port2_var = tk.StringVar(value='COM6')
        self.baudrate_var = tk.StringVar(value='38580')
        self.timeout_var = tk.StringVar(value='20')
        self.message_mode_var = tk.StringVar(value='UTF-8')
        self.message_info = tk.StringVar()
        self.status_var = tk.StringVar(value='未连接 · 先确认两路串口与芯片复位状态')
        self.result_text = tk.StringVar(value='等待执行')
        self.progress_text = tk.StringVar(value='尚未初始化')
        self.step_detail = tk.StringVar(value='连接并初始化后，可单步继续')
        self._style()
        self._build()
        self._configure_family()
        self._update_controls()
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self._poll_id = self.root.after(25, self._poll)

    def _style(self):
        self.root.title('LC01 双芯片密码通信演示')
        left = max(0, (self.root.winfo_screenwidth() - 1320) // 2)
        top = max(0, (self.root.winfo_screenheight() - 940) // 2)
        self.root.geometry(f'1320x900+{left}+{top}')
        self.root.minsize(1120, 780)
        self.root.configure(background=BG)
        self.root.option_add('*TCombobox*Listbox.font', FONT)
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('.', font=FONT, background=BG, foreground=INK)
        style.configure('TFrame', background=BG)
        style.configure('White.TFrame', background='white')
        style.configure('TLabel', background=BG, foreground=INK)
        style.configure('Muted.TLabel', foreground=MUTED)
        style.configure('Title.TLabel', font=('Microsoft YaHei UI', 20, 'bold'))
        style.configure('Section.TLabel', font=('Microsoft YaHei UI', 12, 'bold'))
        style.configure('TButton', padding=(12, 7), borderwidth=1)
        style.map('TButton', foreground=[('disabled', '#77858E')])
        style.configure('Primary.TButton', foreground='white', background=ACCENT)
        style.map('Primary.TButton', background=[('disabled', '#CBD7DD'), ('active', '#0C485D')],
                  foreground=[('disabled', '#536775')])
        style.configure('Stop.TButton', foreground=RED)
        style.configure('TEntry', padding=5, fieldbackground='white')
        style.configure('TCombobox', padding=4, fieldbackground='white')
        style.configure('TNotebook', borderwidth=0, tabmargins=(0, 3, 0, 0))
        style.configure('TNotebook.Tab', padding=(8, 6))
        style.map('TNotebook.Tab', background=[('selected', 'white')],
                  foreground=[('selected', ACCENT)])
        style.configure('Treeview', rowheight=30, background='white', fieldbackground='white')
        style.configure('Treeview.Heading', font=FONT, padding=5)
        style.configure('Horizontal.TProgressbar', background=ACCENT, troughcolor='#E0E8ED')

    def _build(self):
        self.mode_shell = ttk.Frame(self.root, padding=(8, 7, 8, 0))
        self.mode_shell.pack(fill='both', expand=True)
        self.mode_bar = tk.Frame(self.mode_shell, background=BG)
        self.mode_bar.pack(fill='x', pady=(0, 5))
        self.demo_mode_button = tk.Button(
            self.mode_bar, text='算法演示', width=18, height=1, relief='flat', bd=0,
            font=('Microsoft YaHei UI', 10, 'bold'), padx=10, pady=7,
            command=lambda: self.select_mode('demo'))
        self.demo_mode_button.pack(side='left', padx=(0, 6))
        self.communication_mode_button = tk.Button(
            self.mode_bar, text='文本加密通信', width=18, height=1, relief='flat', bd=0,
            font=('Microsoft YaHei UI', 10, 'bold'), padx=10, pady=7,
            command=lambda: self.select_mode('communication'))
        self.communication_mode_button.pack(side='left')
        self.page_stack = ttk.Frame(self.mode_shell)
        self.page_stack.pack(fill='both', expand=True)
        self.page_stack.rowconfigure(0, weight=1)
        self.page_stack.columnconfigure(0, weight=1)
        self.demo_page = ttk.Frame(self.page_stack)
        self.communication_page = ttk.Frame(self.page_stack)
        self.demo_page.grid(row=0, column=0, sticky='nsew')
        self.communication_page.grid(row=0, column=0, sticky='nsew')
        self.communication_page.grid_remove()
        outer = ttk.Frame(self.demo_page, padding=(20, 15, 20, 12))
        outer.pack(fill='both', expand=True)
        top = ttk.Frame(outer)
        top.pack(fill='x', pady=(0, 12))
        ttk.Label(top, text='双芯片算法演示', style='Title.TLabel').pack(side='left')
        self.mode_label = tk.Label(top, font=('Microsoft YaHei UI', 11, 'bold'), padx=14, pady=8)
        self.mode_label.pack(side='right')
        settings = ttk.Frame(outer)
        settings.pack(fill='x')
        settings.columnconfigure(0, weight=3)
        for col in (1, 2, 3, 4):
            settings.columnconfigure(col, weight=1)
        self.algorithm_combo = self._setting(settings, '算法配置', self.algorithm_var, 0,
                                             values=self._profile_labels, width=32, readonly=True)
        self.algorithm_combo.bind('<<ComboboxSelected>>', lambda _: self._configure_family())
        self.port1_combo = self._setting(settings, '芯片1串口', self.port1_var, 1, values=[], width=12)
        self.port2_combo = self._setting(settings, '芯片2串口', self.port2_var, 2, values=[], width=12)
        self._setting(settings, '波特率', self.baudrate_var, 3, width=11)
        self._setting(settings, '命令超时 / 秒', self.timeout_var, 4, width=10)
        mode_row = ttk.Frame(outer)
        mode_row.pack(fill='x', pady=(8, 4))
        self.simulate_check = TickCheckbutton(
            mode_row, text='流程模拟（无硬件）', variable=self.simulate_var,
            command=self._mode_changed, background=BG)
        self.simulate_check.pack(side='left')
        self._config_widgets.append((self.simulate_check, 'normal'))
        self.pause_transfer_check = TickCheckbutton(
            mode_row, text='发送前暂停 / 篡改演示', variable=self.pause_transfer_var,
            background=BG)
        self.pause_transfer_check.pack(side='left', padx=(12, 0))
        self._config_widgets.append((self.pause_transfer_check, 'normal'))
        self.refresh_button = ttk.Button(mode_row, text='刷新串口', command=self.refresh_ports)
        self.refresh_button.pack(side='left', padx=(14, 10))
        ttk.Label(mode_row, text='默认：38580 baud · 读取超时 0.2 s · 步骤间可暂停',
                  style='Muted.TLabel').pack(side='left')
        self.message_frame = ttk.Frame(outer)
        self.message_frame.columnconfigure(1, weight=1)
        ttk.Label(self.message_frame, text='签名消息').grid(row=0, column=0, sticky='w', padx=(0, 12))
        self.message_input = tk.Text(self.message_frame, height=1, width=45, wrap='word',
                                     font=FONT, relief='solid', borderwidth=1,
                                     background='white', foreground=INK, insertbackground=ACCENT,
                                     selectbackground='#CDE6F1', undo=True)
        self.message_input.grid(row=0, column=1, sticky='ew', pady=4)
        self.message_input.insert('1.0', 'HEU dual chip demo')
        self.message_input.bind('<<Modified>>', self._message_changed)
        self.message_input.edit_modified(False)
        self.message_mode_combo = ttk.Combobox(self.message_frame, width=8, state='readonly',
                                               textvariable=self.message_mode_var, values=('UTF-8', 'HEX'))
        self.message_mode_combo.grid(row=0, column=2, padx=(10, 0))
        self.message_mode_combo.bind('<<ComboboxSelected>>', lambda _: self._validate_message_preview())
        self._config_widgets.append((self.message_mode_combo, 'readonly'))
        ttk.Label(self.message_frame, textvariable=self.message_info, style='Muted.TLabel').grid(
            row=1, column=1, columnspan=2, sticky='w')
        toolbar = ttk.Frame(outer)
        toolbar.pack(fill='x', pady=(12, 10))
        self.buttons = {}
        for key, text, command, style in (
            ('connect', '连接并初始化', self.connect, 'Primary.TButton'),
            ('step', '单步', self.start_step, 'TButton'),
            ('run', '一键运行', self.start_run, 'Primary.TButton'),
            ('stop', '停止', self.stop, 'Stop.TButton'),
            ('disconnect', '断开', self.disconnect, 'TButton'),
            ('export', '导出记录', self.export, 'TButton'),
            ('tamper', '篡改 / 对比', self.open_transfer_editor, 'TButton'),
        ):
            button = ttk.Button(toolbar, text=text, command=command, style=style)
            button.pack(side='left', padx=(0, 7))
            self.buttons[key] = button
        self.status_label = ttk.Label(outer, textvariable=self.status_var, style='Muted.TLabel',
                                      wraplength=1050)
        self.status_label.pack(fill='x', pady=(0, 10))
        ttk.Label(outer, text='字段：正常序完整 HEX · 私钥只在芯片1使用 · 停止在当前步骤结束后生效',
                  style='Muted.TLabel').pack(side='bottom', fill='x', pady=(9, 0))
        self.vertical_panes = ttk.Panedwindow(outer, orient='vertical')
        self.vertical_panes.pack(fill='both', expand=True)
        workspace = ttk.Frame(self.vertical_panes)
        workspace.columnconfigure(0, weight=1, uniform='chip')
        workspace.columnconfigure(1, weight=0, minsize=314)
        workspace.columnconfigure(2, weight=1, uniform='chip')
        workspace.rowconfigure(1, weight=1)
        self.left_title = ttk.Label(workspace, text='芯片1 · 密钥拥有方', style='Section.TLabel')
        self.left_title.grid(row=0, column=0, sticky='w', pady=(2, 6))
        self.right_title = ttk.Label(workspace, text='芯片2 · 封装方', style='Section.TLabel')
        self.right_title.grid(row=0, column=2, sticky='w', pady=(2, 6))
        self.left_notebook = ttk.Notebook(workspace)
        self.left_notebook.grid(row=1, column=0, sticky='nsew')
        self.right_notebook = ttk.Notebook(workspace)
        self.right_notebook.grid(row=1, column=2, sticky='nsew')
        for name in ('pk', 'sk', 'k1', 'message', 'signature', 'received_ct'):
            self._field_tab(self.left_notebook, name)
        for name in ('ct', 'k2', 'verify_response', 'received_pk', 'received_signature', 'received_message'):
            self._field_tab(self.right_notebook, name)
        self.left_notebook.bind('<<NotebookTabChanged>>', self._sync_field_selection)
        self.right_notebook.bind('<<NotebookTabChanged>>', self._sync_field_selection)
        center = ttk.Frame(workspace, padding=(12, 0))
        center.grid(row=0, column=1, rowspan=2, sticky='nsew')
        center.columnconfigure(0, weight=1)
        center.rowconfigure(2, weight=1, minsize=64)
        self.diagram = tk.Canvas(center, height=76, width=290, background=BG, highlightthickness=0)
        self.diagram.grid(row=0, column=0, sticky='ew')
        self.diagram.bind('<Configure>', lambda _: self._draw_transfers())
        ttk.Label(center, text='执行步骤', style='Section.TLabel').grid(row=1, column=0, sticky='w', pady=(2, 4))
        step_frame = ttk.Frame(center)
        step_frame.grid(row=2, column=0, sticky='nsew')
        step_frame.columnconfigure(0, weight=1)
        step_frame.rowconfigure(0, weight=1)
        self.step_tree = ttk.Treeview(step_frame, columns=('state',), show='tree headings', height=6,
                                      selectmode='browse')
        self.step_tree.heading('#0', text='流程')
        self.step_tree.heading('state', text='状态')
        self.step_tree.column('#0', width=209, minwidth=150, stretch=True)
        self.step_tree.column('state', width=56, minwidth=52, stretch=False, anchor='center')
        self.step_tree.grid(row=0, column=0, sticky='nsew')
        scroll = ttk.Scrollbar(step_frame, orient='vertical', command=self.step_tree.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        hscroll = ttk.Scrollbar(step_frame, orient='horizontal', command=self.step_tree.xview)
        hscroll.grid(row=1, column=0, sticky='ew')
        self.step_tree.configure(yscrollcommand=scroll.set, xscrollcommand=hscroll.set)
        self.step_tree.bind('<<TreeviewSelect>>', self._selected_step)
        for tag, color in (('done', GREEN), ('running', ACCENT), ('error', RED), ('pending', MUTED)):
            self.step_tree.tag_configure(tag, foreground=color)
        self.step_tree.insert('', 'end', iid='empty', text='初始化后显示完整流程', values=('待连接',))
        self.progress = ttk.Progressbar(center, mode='determinate')
        self.progress.grid(row=3, column=0, sticky='ew', pady=(6, 3))
        ttk.Label(center, textvariable=self.progress_text, style='Muted.TLabel').grid(row=4, column=0, sticky='w')
        self.result_label = tk.Label(center, textvariable=self.result_text, background='#E5ECF1', foreground=MUTED,
                                     font=('Microsoft YaHei UI', 10, 'bold'), padx=10, pady=5,
                                     wraplength=268, anchor='w', justify='left')
        self.result_label.grid(row=5, column=0, sticky='ew', pady=(5, 0))
        self.vertical_panes.add(workspace, weight=4)
        logs = ttk.Frame(self.vertical_panes, padding=(0, 10, 0, 0))
        logs.rowconfigure(1, weight=1)
        logs.columnconfigure(0, weight=1)
        ttk.Label(logs, text='实时通信日志', style='Section.TLabel').grid(row=0, column=0, sticky='w', pady=(0, 5))
        ttk.Label(logs, text='原始 TX / RX 随会话导出', style='Muted.TLabel').grid(row=0, column=1, sticky='e')
        self.log_widget = tk.Text(logs, height=4, width=80, wrap='none', font=('Consolas', 10),
                                  background='white', foreground=INK, relief='flat', state='disabled',
                                  padx=9, pady=7, selectbackground='#CDE6F1')
        self.log_widget.grid(row=1, column=0, columnspan=2, sticky='nsew')
        log_scroll = ttk.Scrollbar(logs, orient='vertical', command=self.log_widget.yview)
        log_scroll.grid(row=1, column=2, sticky='ns')
        log_x = ttk.Scrollbar(logs, orient='horizontal', command=self.log_widget.xview)
        log_x.grid(row=2, column=0, columnspan=2, sticky='ew')
        self.log_widget.configure(yscrollcommand=log_scroll.set, xscrollcommand=log_x.set)
        self.log_widget.tag_configure('error', foreground=RED)
        self.log_widget.bind('<Control-a>', self._select_all)
        self.vertical_panes.add(logs, weight=1)
        from communication_panel import CommunicationPanel
        self.communication_panel = CommunicationPanel(self, self.communication_page)
        self.communication_panel.pack(fill='both', expand=True)
        self._render_mode_buttons()

    def _setting(self, parent, label, variable, column, values=None, width=12, readonly=False):
        frame = ttk.Frame(parent, padding=(0, 0, 10 if column < 4 else 0, 0))
        frame.grid(row=0, column=column, sticky='ew')
        ttk.Label(frame, text=label).pack(anchor='w', pady=(0, 5))
        if values is not None:
            widget = ttk.Combobox(frame, textvariable=variable, values=values, width=width,
                                   state='readonly' if readonly else 'normal')
        else:
            widget = ttk.Entry(frame, textvariable=variable, width=width)
        widget.pack(fill='x')
        self._config_widgets.append((widget, 'readonly' if readonly else 'normal'))
        return widget

    def select_mode(self, mode):
        """Switch main-window modes and release the other mode's idle session."""
        if mode not in ('demo', 'communication'):
            raise ValueError('未知主窗口模式')
        target = self.communication_page if mode == 'communication' else self.demo_page
        if self._current_mode == mode and target.winfo_manager():
            return True
        if self.closing:
            return False
        panel = self.communication_panel
        if mode == 'communication':
            if self.busy or (panel is not None and panel.busy):
                return False
            if self.session is not None:
                self.disconnect()
        else:
            if panel is not None and panel.busy:
                return False
            if panel is not None and panel.session is not None:
                panel.disconnect()
        self._current_mode = mode
        if mode == 'communication':
            self.demo_page.grid_remove()
            self.communication_page.grid()
        else:
            self.communication_page.grid_remove()
            self.demo_page.grid()
        self._render_mode_buttons()
        self._update_controls()
        if mode == 'communication' and self.communication_panel is not None:
            self.communication_panel.on_shown()
        return True

    def _render_mode_buttons(self):
        active = {'background': ACCENT, 'foreground': 'white',
                  'activebackground': '#0C485D', 'activeforeground': 'white'}
        inactive = {'background': '#E1E9EE', 'foreground': INK,
                    'activebackground': '#D2DFE6', 'activeforeground': INK}
        self.demo_mode_button.configure(**(active if self._current_mode == 'demo' else inactive))
        self.communication_mode_button.configure(
            **(active if self._current_mode == 'communication' else inactive))

    def _field_tab(self, notebook, name):
        frame = ttk.Frame(notebook, style='White.TFrame', padding=8)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        header = ttk.Frame(frame, style='White.TFrame')
        header.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 7))
        count = tk.StringVar(value='尚未读取')
        button = ttk.Button(header, text='复制完整 HEX', command=lambda key=name: self.copy_field(key))
        button.pack(side='right', anchor='n')
        tk.Label(header, textvariable=count, foreground=MUTED, background='white', font=FONT,
                 justify='left', anchor='w').pack(side='left', anchor='n')
        if name.startswith('received_'):
            tk.Label(frame, text='接收/输入（已获响应）· 非硬件读回', foreground=MUTED,
                     background='white', font=('Microsoft YaHei UI', 9), anchor='w').grid(
                         row=2, column=0, columnspan=2, sticky='ew', pady=(4, 0))
        widget = tk.Text(frame, width=22, height=10, wrap='char', background='white', foreground=INK,
                         font=MONO, relief='flat', state='disabled', padx=3, pady=5,
                         selectbackground='#CDE6F1', selectforeground=INK)
        widget.grid(row=1, column=0, sticky='nsew')
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=widget.yview)
        scrollbar.grid(row=1, column=1, sticky='ns')
        widget.configure(yscrollcommand=scrollbar.set)
        widget.tag_configure('diff', foreground=RED, background='#FFE0E3')
        widget.bind('<Control-a>', self._select_all)
        widget.bind('<Control-A>', self._select_all)
        self.field_widgets[name] = widget
        self.field_lengths[name] = count
        self.copy_buttons[name] = button
        self.field_tabs[name] = (notebook, frame)
        notebook.add(frame, text=FIELD_NAMES[name])

    @staticmethod
    def _select_all(event):
        event.widget.tag_add('sel', '1.0', 'end-1c')
        event.widget.mark_set('insert', '1.0')
        return 'break'

    @property
    def algorithm_key(self):
        return self._profile_keys[self._profile_labels.index(self.algorithm_var.get())]

    def select_algorithm(self, key):
        if self.busy or self.session is not None:
            raise RuntimeError('请先断开当前会话再切换算法')
        self.algorithm_var.set(self._profile_labels[self._profile_keys.index(key)])
        self._configure_family()

    def _configure_family(self):
        signature = PROFILES[self.algorithm_key].family == 'signature'
        # pack before the toolbar's following siblings, keeping the input above actions.
        if signature:
            self.message_frame.pack(fill='x', after=self.simulate_check.master, pady=(5, 0))
        else:
            self.message_frame.pack_forget()
        self.right_title.configure(text='芯片2 · 验签方' if signature else '芯片2 · 封装方')
        visible = ({'pk', 'sk', 'message', 'signature', 'verify_response', 'received_pk',
                    'received_signature', 'received_message'} if signature else
                   {'pk', 'sk', 'ct', 'k1', 'k2', 'received_pk', 'received_ct'})
        for name, (notebook, frame) in self.field_tabs.items():
            if name in visible:
                notebook.add(frame, text=FIELD_NAMES[name])
            else:
                notebook.hide(frame)
        self.left_notebook.select(self.field_tabs['pk'][1])
        self.right_notebook.select(self.field_tabs['verify_response' if signature else 'ct'][1])
        self._mode_changed()
        self._validate_message_preview()
        self._draw_transfers()

    def _mode_changed(self):
        if self.simulate_var.get():
            self.mode_label.configure(text='流程模拟 · 非密码算法验证', background='#FFF1CB', foreground=AMBER)
        else:
            self.mode_label.configure(text='真实双芯片 · 硬件模式', background='#E1ECF1', foreground=ACCENT)

    def _draw_transfers(self):
        self.diagram.delete('all')
        width = max(270, self.diagram.winfo_width())
        signature = PROFILES[self.algorithm_key].family == 'signature'
        self.diagram.create_text(width / 2, 8, text='芯片间数据流', fill=MUTED, font=FONT)
        self.diagram.create_line(12, 39, width - 12, 39, arrow='last', width=2, fill=ACCENT)
        self.diagram.create_text(width / 2, 26, text='公钥 + 原消息 + 签名' if signature else '公钥 PK',
                                  fill=ACCENT, font=FONT)
        if not signature:
            self.diagram.create_line(width - 12, 75, 12, 75, arrow='last', width=2, fill=ACCENT)
            self.diagram.create_text(width / 2, 61, text='密文 CT', fill=ACCENT, font=FONT)
        else:
            self.diagram.create_text(width / 2, 63, text='私钥留在芯片1 · 芯片2返回验签响应',
                                      fill=MUTED, font=('Microsoft YaHei UI', 9))

    def _selected_step(self, _event=None):
        selected = self.step_tree.selection()
        if selected and selected[0].isdigit():
            index = int(selected[0])
            if index < len(self.steps) and not self.busy and not self.closing:
                self.status_var.set(f'步骤 {index + 1}：{self.steps[index]}')

    def message_bytes(self):
        text = self.message_input.get('1.0', 'end-1c')
        if self.message_mode_var.get() == 'HEX':
            try:
                data = bytes.fromhex(text)
            except ValueError as exc:
                raise ValueError('HEX 消息须为完整字节（两个十六进制字符一组，可含空白）') from exc
        else:
            data = text.encode('utf-8')
        if not 1 <= len(data) <= 1000 or len(data) % 8 == 0:
            raise ValueError(f'消息实际 {len(data)} 字节；须为 1..1000 字节，且不能是 8 的倍数。请修改输入。')
        return data

    def _message_changed(self, _event=None):
        if self.message_input.edit_modified():
            self.message_input.edit_modified(False)
            self._validate_message_preview()

    def _validate_message_preview(self):
        try:
            data = self.message_bytes()
            self.message_info.set(f'{len(data)} 字节 · 合法范围 1..1000 字节，排除 8 的倍数 · 按原消息签名')
        except ValueError as exc:
            self.message_info.set(str(exc))

    def _config(self):
        try:
            baudrate = int(self.baudrate_var.get())
            timeout = float(self.timeout_var.get())
        except ValueError as exc:
            raise ValueError('波特率须为正整数，命令超时须为正数（秒）') from exc
        if baudrate <= 0 or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('波特率与命令超时须为大于零的有效数值')
        port1, port2 = self.port1_var.get().strip(), self.port2_var.get().strip()
        if not self.simulate_var.get() and (not port1 or not port2 or port1.casefold() == port2.casefold()):
            raise ValueError('请为两颗芯片填写不同的 COM 端口，再连接初始化')
        message = self.message_bytes() if PROFILES[self.algorithm_key].family == 'signature' else b'HEU dual chip demo'
        return DemoConfig(algorithm=self.algorithm_key, port1=port1, port2=port2, baudrate=baudrate,
                          command_timeout=timeout, simulate=self.simulate_var.get(), message=message,
                          pause_before_transfer=self.pause_transfer_var.get())

    def _update_controls(self):
        editor_open = self.transfer_editor is not None
        panel_busy = self.communication_panel is not None and self.communication_panel.busy
        panel_session = (self.communication_panel is not None
                         and self.communication_panel.session is not None
                         and not self.communication_panel.session.closed)
        locked = self.busy or self.session is not None or self.closing or editor_open or panel_busy
        for widget, state in self._config_widgets:
            widget.configure(state='disabled' if locked else state)
        self.message_input.configure(state='disabled' if locked else 'normal')
        self.refresh_button.configure(state='disabled' if locked else 'normal')
        complete = self.result is not None
        states = {
            'connect': not self.busy and not panel_busy and not panel_session and self.session is None,
            'step': not self.busy and not panel_busy and not panel_session and not self._failed and not complete,
            'run': not self.busy and not panel_busy and not panel_session and not self._failed and not complete,
            'stop': self.busy and self._job_kind in ('connect', 'step', 'run') and not self._stop_requested.is_set(),
            'disconnect': not self.busy and self.session is not None,
            'export': not self.busy and self.session is not None,
            'tamper': not self.busy and self.session is not None,
        }
        for key, button in self.buttons.items():
            button.configure(state='normal' if states[key] and not self.closing and not editor_open else 'disabled')
        for name, button in self.copy_buttons.items():
            button.configure(state='normal' if name in self.fields and not self.closing else 'disabled')
        if self.communication_panel is not None:
            self.communication_panel.refresh_controls()

    def _reset_display(self):
        self.fields.clear()
        self.result = None
        self.tampered = False
        self.pause_message = ''
        self._failed = False
        self.last_error = ''
        self.steps = []
        self.step_states.clear()
        self.step_tree.delete(*self.step_tree.get_children())
        for widget in self.field_widgets.values():
            widget.configure(state='normal')
            widget.delete('1.0', 'end')
            widget.configure(state='disabled')
        for length in self.field_lengths.values():
            length.set('尚未读取')
        self.result_text.set('等待执行')
        self.result_label.configure(background='#E5ECF1', foreground=MUTED)
        self.progress.configure(value=0, maximum=1)
        self.progress_text.set('正在创建会话')

    def connect(self):
        if self.session is None:
            self._launch('connect')

    def start_step(self):
        self._launch('step')

    def start_run(self):
        self._launch('run')

    def open_transfer_editor(self):
        if self.transfer_editor is not None:
            self.transfer_editor.window.lift()
            return self.transfer_editor
        if self.busy or self.session is None or self.closing:
            return None
        from transfer_editor import TransferEditor
        self.transfer_editor = TransferEditor(self)
        self._update_controls()
        return self.transfer_editor

    def refresh_ports(self):
        if not self.busy and self.session is None:
            self._launch('refresh')

    def export(self, directory=None):
        if self.busy or self.session is None or self.closing:
            return
        if directory is None:
            directory = filedialog.askdirectory(parent=self.root, title='选择导出父目录（自动创建时间戳子目录）')
        if directory:
            self._launch('export', directory=Path(directory))

    def disconnect(self):
        if self.session is not None and not self.busy:
            self._launch('disconnect')

    def _launch(self, kind, directory=None):
        if (self.busy or self.transfer_editor is not None
                or (self.communication_panel is not None and self.communication_panel.busy)
                or (self.communication_panel is not None
                    and self.communication_panel.session is not None
                    and not self.communication_panel.session.closed)
                or (self.closing and kind != 'disconnect')):
            return
        if kind in ('step', 'run') and (self._failed or self.result is not None):
            return
        config = None
        if kind in ('connect', 'step', 'run') and self.session is None:
            try:
                config = self._config()
            except ValueError as exc:
                self._problem(str(exc))
                return
            self._reset_display()
        existing = self.session
        self._stop_requested.clear()
        self.busy = True
        self._job_kind = kind
        if kind in ('connect', 'step', 'run'):
            self.pause_message = ''
        self.status_var.set({'connect': '正在连接并初始化两颗芯片…', 'step': '正在执行下一步…',
                             'run': '正在运行剩余步骤…', 'refresh': '正在枚举串口（不会打开端口）…',
                             'disconnect': '正在释放两路串口…', 'export': '正在导出记录…'}[kind])
        self._update_controls()

        def work():
            working = existing
            outcome = {'kind': kind, 'error': None, 'session': working}

            def emit(event):
                self._events.put(event)
                # Core run() clears its stop flag at entry. Reapply at the step boundary
                # so an early GUI stop cannot be lost in that entry race.
                if event.get('type') == 'step' and event.get('state') == 'done' and self._stop_requested.is_set():
                    if working is not None:
                        working.stop()

            try:
                if kind == 'refresh':
                    from serial.tools import list_ports
                    outcome['ports'] = [port.device for port in list_ports.comports()]
                elif kind == 'disconnect':
                    working.close()
                    outcome['session'] = None
                elif kind == 'export':
                    outcome['export'] = working.export(directory)
                else:
                    if working is None:
                        working = DemoSession(config, emit=emit)
                        outcome['session'] = working
                        self._events.put({'type': '_session', 'session': working, 'steps': list(working.steps)})
                    if not self._stop_requested.is_set():
                        if kind == 'run':
                            working.run()
                        else:
                            working.step()
                    outcome['next_step'] = working.next_step
            except Exception as exc:
                outcome['error'] = str(exc)
            finally:
                outcome['stopped'] = self._stop_requested.is_set()
                self._events.put({'type': '_finished', 'outcome': outcome})

        self.worker = threading.Thread(target=work, name=f'LC01-{kind}', daemon=False)
        self.worker.start()

    def stop(self):
        if self.busy and self._job_kind in ('connect', 'step', 'run'):
            self._stop_requested.set()
            if self.session is not None:
                self.session.stop()
            self.status_var.set('已请求停止 · 等待当前步骤结束后停止，可继续执行')
            self._update_controls()

    def close(self):
        if self.closing or self.destroyed:
            return
        self.closing = True
        if self.transfer_editor is not None:
            self.transfer_editor.close()
        self.stop()
        self.status_var.set('正在关闭 · 等待当前步骤结束并释放串口，请稍候…')
        self._update_controls()
        if self.communication_panel is not None:
            self.communication_panel.close()
        if not self.busy:
            if self.session is not None:
                self._launch('disconnect')
            else:
                self._maybe_destroy()

    def _destroy(self):
        if self.destroyed:
            return
        if self.busy or self.session is not None:
            return
        if self.communication_panel is not None and not self.communication_panel.shutdown_complete:
            return
        self.destroyed = True
        if self._poll_id is not None:
            self.root.after_cancel(self._poll_id)
            self._poll_id = None
        self.root.destroy()

    def _maybe_destroy(self):
        if not self.closing or self.destroyed:
            return
        if self.busy or self.session is not None:
            return
        if self.communication_panel is not None and not self.communication_panel.shutdown_complete:
            return
        self._destroy()

    def _poll(self):
        self._poll_id = None
        for _ in range(500):
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            self._handle(event)
        if self._pending_done is not None and not self.worker.is_alive():
            outcome = self._pending_done
            self._pending_done = None
            self._finish(outcome)
        if not self.destroyed:
            self._poll_id = self.root.after(25, self._poll)
        elif self.closing:
            self._maybe_destroy()

    def _handle(self, event):
        kind = event.get('type')
        if kind in self.events_seen:
            self.events_seen[kind] += 1
        if kind == 'log':
            self._log(event['message'])
        elif kind == 'field':
            self._set_field(event['name'], event['data'])
        elif kind == 'step':
            index, state = event['index'], event['state']
            self.step_states[index] = state
            self.step_tree.item(str(index), values=({'running': '执行中', 'done': '完成', 'error': '失败'}[state],), tags=(state,))
            self.step_tree.see(str(index))
            if state == 'running' and not self.closing and not self._stop_requested.is_set():
                self.status_var.set(f'正在执行：{event["name"]}')
            done = sum(value == 'done' for value in self.step_states.values())
            self.progress.configure(value=done)
            self.progress_text.set(f'已完成 {done} / {len(self.steps)} 步')
        elif kind == 'result':
            self.result = bool(event['ok'])
            self.tampered = bool(event.get('tampered', self.tampered))
            prefix = '模拟流程' if self.simulate_var.get() else '硬件结果'
            self.result_text.set(f'{prefix} · {"通过" if self.result else "失败"}\n{event["message"]}')
            self.result_label.configure(foreground=GREEN if self.result else RED,
                                        background='#E6F3EB' if self.result else '#FBEAEC')
            if not self.closing:
                self.status_var.set(event['message'])
            if 'k1' in self.fields:
                self.left_notebook.select(self.field_tabs['k1'][1])
                self.right_notebook.select(self.field_tabs['k2'][1])
        elif kind == 'pause':
            self.pause_message = event['message']
            self.status_var.set(f'{self.pause_message} · 可点击“篡改 / 对比”编辑，或“一键运行”继续')
        elif kind == 'transfer':
            if event.get('changed_offsets'):
                self.tampered = True
        elif kind == '_session':
            self.session = event['session']
            self.steps = event['steps']
            self.step_tree.delete(*self.step_tree.get_children())
            for index, name in enumerate(self.steps):
                self.step_tree.insert('', 'end', iid=str(index), text=f'{index + 1}. {name}',
                                      values=('待执行',), tags=('pending',))
            self.progress.configure(maximum=len(self.steps))
            if self._stop_requested.is_set():
                self.session.stop()
        elif kind == '_finished':
            self._pending_done = event['outcome']

    def _finish(self, outcome):
        self.busy = False
        self.worker = None
        kind = outcome['kind']
        self.session = outcome['session']
        if outcome['error']:
            if kind in ('connect', 'step', 'run'):
                self._failed = True
                self.result_text.set('通信中止\n可导出已有记录，断开后重新连接')
                self.result_label.configure(foreground=RED, background='#FBEAEC')
            self._problem(outcome['error'])
        elif kind == 'disconnect':
            self.session = None
            self._failed = False
            # Preserve the completed display, but allow the next session to be created.
            self.result = None
            self.status_var.set('已断开 · 字段保留供复制；可修改配置并重新初始化')
        elif kind == 'refresh':
            ports = outcome.get('ports', [])
            self.port1_combo.configure(values=ports)
            self.port2_combo.configure(values=ports)
            self.status_var.set('可用串口：' + ('、'.join(ports) if ports else '未发现；可手动填写 COM 端口'))
        elif kind == 'export':
            self.last_export = Path(outcome['export'])
            self.status_var.set(f'已导出：{self.last_export}')
        elif self.result is not None:
            self.status_var.set('流程完成 · 可复制字段或导出全部记录，重新演示请先断开')
        elif self.session is not None and self.session.waiting_for_transfer is not None:
            prompt = self.pause_message or f'发送前暂停：{self.steps[self.session.next_step]}'
            self.status_var.set(f'{prompt} · 可“篡改 / 对比”编辑，或“一键运行”继续')
        elif outcome['stopped']:
            self.status_var.set('已停止 · 当前步骤已结束，单步或一键可继续')
        else:
            index = outcome.get('next_step', 0)
            next_name = self.steps[index] if index < len(self.steps) else '流程完成'
            self.status_var.set(f'会话已就绪 · 下一步：{next_name}')
        self._update_controls()
        if self.closing:
            if self.session is not None:
                # If close itself failed, release the GUI reference and still finish shutdown.
                if kind == 'disconnect':
                    self.session = None
                    self._maybe_destroy()
                else:
                    self._launch('disconnect')
            else:
                self._maybe_destroy()

    def _set_field(self, name, data):
        data = bytes(data)
        self.fields[name] = data
        if name not in self.field_widgets:
            return
        widget = self.field_widgets[name]
        widget.configure(state='normal')
        widget.delete('1.0', 'end')
        widget.insert('1.0', data.hex().upper())
        widget.configure(state='disabled')
        self.field_lengths[name].set(f'{len(data):,} B · 正常序 HEX')
        self._refresh_comparisons()
        self.copy_buttons[name].configure(state='normal' if not self.closing else 'disabled')
        notebook, frame = self.field_tabs[name]
        if str(notebook.tab(frame, 'state')) != 'hidden':
            notebook.select(frame)

    def _refresh_comparisons(self):
        for source, received in COMPARE_PAIRS:
            left, right = self.fields.get(source), self.fields.get(received)
            for name in (source, received):
                self.field_widgets[name].tag_remove('diff', '1.0', 'end')
            offsets = []
            if left is not None and right is not None:
                offsets = diff_offsets(left, right)
                state = f'差异 {len(offsets)} B' if offsets else '与对端一致'
            else:
                state = '等待对端'
            for name in (source, received):
                if name not in self.fields:
                    continue
                data = self.fields[name]
                self.field_lengths[name].set(f'{len(data):,} B · 正常序 HEX\n{state}')
                widget = self.field_widgets[name]
                for offset in offsets:
                    if offset < len(data):
                        widget.tag_add('diff', f'1.0+{offset * 2}c', f'1.0+{offset * 2 + 2}c')

    def _sync_field_selection(self, event):
        selected = event.widget.select()
        name = next((key for key, (_, tab) in self.field_tabs.items() if str(tab) == selected), None)
        for first, second in COMPARE_PAIRS:
            if name not in (first, second):
                continue
            peer = second if name == first else first
            notebook, tab = self.field_tabs[peer]
            if notebook.tab(tab, 'state') != 'hidden' and notebook.select() != str(tab):
                notebook.select(tab)
            break

    def copy_field(self, name):
        if name in self.fields:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.fields[name].hex().upper())
            self.status_var.set(f'已复制 {FIELD_NAMES.get(name, name)}：{len(self.fields[name])} 字节完整 HEX')

    def _log(self, text, error=False):
        at_bottom = self.log_widget.yview()[1] >= 0.98
        self.log_widget.configure(state='normal')
        self.log_widget.insert('end', text + '\n', ('error',) if error else ())
        self.log_widget.configure(state='disabled')
        if at_bottom:
            self.log_widget.see('end')

    def _problem(self, message):
        self.last_error = message
        self.status_var.set(f'操作未完成：{message}')
        self._log(f'界面提示：{message}', error=True)
