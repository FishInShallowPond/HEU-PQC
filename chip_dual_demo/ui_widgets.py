"""Small Tk widgets with deterministic cross-theme check marks."""
from __future__ import annotations

import tkinter as tk


class TickCheckbutton(tk.Frame):
    """Boolean selector whose checked state is an explicit check mark."""

    def __init__(self, parent, *, text, variable, command=None,
                 background='#F7FAFB', foreground='#182D3D'):
        super().__init__(parent, background=background)
        self.variable = variable
        self.command = command
        self._text = text
        self._background = background
        self._foreground = foreground
        self._state = 'normal'
        self.indicator = tk.Button(
            self, width=2, height=1, relief='flat', bd=0, padx=0, pady=0,
            background='white', foreground='#135C75', activebackground='white',
            activeforeground='#135C75', font=('Segoe UI Symbol', 11, 'bold'),
            command=self._toggle)
        self.indicator.pack(side='left')
        self.label = tk.Label(self, text=text, background=background,
                              foreground=foreground, font=('Microsoft YaHei UI', 9))
        self.label.pack(side='left', padx=(3, 0))
        self.label.bind('<Button-1>', lambda _event: self._toggle())
        self._trace = variable.trace_add('write', lambda *_: self._refresh())
        self._refresh()

    def _toggle(self):
        if self._state == 'disabled':
            return
        self.variable.set(not bool(self.variable.get()))
        self._refresh()
        if self.command is not None:
            self.command()

    def get(self):
        return bool(self.variable.get())

    def set(self, value):
        self.variable.set(bool(value))

    def _refresh(self):
        self.indicator.configure(text='✓' if self.get() else '')

    def configure(self, cnf=None, **kwargs):
        state = kwargs.pop('state', None)
        if cnf is not None and isinstance(cnf, dict) and 'state' in cnf:
            state = cnf.pop('state')
        if state is not None:
            self._state = state
            disabled = state == 'disabled'
            self.indicator.configure(state='disabled' if disabled else 'normal',
                                     background='#E5EAED' if disabled else 'white',
                                     foreground='#8A99A3' if disabled else '#135C75')
            self.label.configure(foreground='#8A99A3' if disabled else self._foreground)
        if cnf is not None:
            super().configure(cnf, **kwargs)
        elif kwargs:
            super().configure(**kwargs)
        return None

    config = configure
