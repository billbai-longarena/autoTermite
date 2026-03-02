#!/usr/bin/env python3
"""GUI controller for per-process Termite automation settings."""

from __future__ import annotations

import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox
from tkinter import ttk

from termite_process_utils import (
    CONFIG_FILE,
    DEFAULT_PROCESS_CONFIG,
    RUNTIME_STATUS_FILE,
    atomic_read_modify_write,
    find_active_agent_processes,
    find_orphan_agent_processes,
    get_effective_process_config,
    load_runtime_status,
    load_process_config,
    terminate_process,
)

REFRESH_INTERVAL_MS = 3000
BG_BASE = "#f4f6fb"
BG_CARD = "#ffffff"
FG_MAIN = "#1f2937"
FG_MUTED = "#6b7280"

TASK_TYPE_OPTIONS = [
    "审计",
    "基于网络的客户需求研究和市场研究并形成开发需求",
    "AB测试和转化漏斗设计",
    "自主根据任务优先级选择",
    "你是自由的",
    "白蚁协议",
]


class TermiteControlGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Termite Process Control")
        self.geometry("1560x860")
        self.minsize(1150, 700)

        self.config_path = CONFIG_FILE
        self.config_data = {"processes": {}, "global_pause": False}
        self.runtime_path = RUNTIME_STATUS_FILE
        self.runtime_status = {"daemon": {}, "metrics": {}, "processes": {}}

        self.active_by_key = {}
        self.orphan_by_pid = {}
        self.selected_process_key = None
        self._refresh_in_progress = False  # 3A: prevent overlapping background refreshes
        self._refresh_result = None        # 3A: thread writes here, main thread polls
        self._refresh_update_inputs = True

        self.auto_refresh_var = tk.BooleanVar(value=True)
        self.enable_agent_team_var = tk.BooleanVar(value=DEFAULT_PROCESS_CONFIG["enable_agent_team"])
        self.automate_process_var = tk.BooleanVar(value=DEFAULT_PROCESS_CONFIG["automate_process"])
        self.new_chat_on_done_var = tk.BooleanVar(value=DEFAULT_PROCESS_CONFIG["new_chat_on_done"])
        self.max_tasks_var = tk.StringVar(value=str(DEFAULT_PROCESS_CONFIG["max_tasks"]))

        self.selected_process_text = tk.StringVar(value="Selected: <none>")
        self.status_text = tk.StringVar(value=f"Config file: {self.config_path}")
        self.daemon_status_text = tk.StringVar(value="Daemon: unknown")
        self.last_action_text = tk.StringVar(value="Last action: -")
        self.task_probability_text = tk.StringVar(value="每次发放任务会按权重重新抽签。")
        self.global_pause_var = tk.BooleanVar(value=False)

        self.task_type_vars = {}
        self.task_weight_vars = {}
        for option in TASK_TYPE_OPTIONS:
            self.task_type_vars[option] = tk.BooleanVar(value=False)
            self.task_weight_vars[option] = tk.StringVar(value="10")
            self.task_type_vars[option].trace_add("write", lambda *_: self._update_task_probability_text())
            self.task_weight_vars[option].trace_add("write", lambda *_: self._update_task_probability_text())

        self._setup_styles()
        self._build_layout()
        self.refresh_all()
        self.after(REFRESH_INTERVAL_MS, self._auto_refresh_tick)
        
        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _on_closing(self) -> None:
        choice = messagebox.askyesnocancel("Exit", "Do you also want to stop the background daemon (termite_daemon.py)?\n\nYes: Stop daemon and exit GUI (requires admin password)\nNo: Keep daemon running, just exit GUI\nCancel: Go back to GUI")
        
        if choice is None:
            # User clicked Cancel
            return
            
        if choice:
            # User clicked Yes
            try:
                import subprocess
                daemon, _ = self._daemon_runtime()
                daemon_pid = daemon.get("pid")
                try:
                    daemon_pid = int(daemon_pid)
                except (TypeError, ValueError):
                    daemon_pid = 0

                if daemon_pid > 1:
                    kill_cmd = f"kill {daemon_pid}"
                else:
                    kill_cmd = "pkill -f termite_daemon.py"
                # Use osascript to show macOS native password/Touch ID prompt
                script = f'do shell script "{kill_cmd}" with administrator privileges'
                subprocess.run(["osascript", "-e", script], check=False)
                messagebox.showinfo("Exit", "Background daemon stopped. Exiting GUI.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop daemon: {e}")
                
        # Both Yes and No will eventually reach here
        self.destroy()

    def _setup_styles(self) -> None:
        self.configure(bg=BG_BASE)
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        style.configure("TFrame", background=BG_BASE)
        style.configure("Card.TFrame", background=BG_CARD)
        style.configure("TLabel", background=BG_BASE, foreground=FG_MAIN)
        style.configure("Muted.TLabel", background=BG_BASE, foreground=FG_MUTED)
        style.configure("TButton", padding=(10, 6))
        style.configure("TCheckbutton", background=BG_BASE, foreground=FG_MAIN)
        style.configure(
            "TLabelframe",
            background=BG_BASE,
            borderwidth=1,
            relief="solid",
            padding=8,
        )
        style.configure("TLabelframe.Label", background=BG_BASE, foreground=FG_MAIN, font=("TkDefaultFont", 11, "bold"))
        style.configure("Treeview", rowheight=28, borderwidth=0, relief="flat")
        style.configure("Treeview.Heading", padding=(8, 6), font=("TkDefaultFont", 10, "bold"))
        style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", "#111827")])
        style.configure("Vertical.TScrollbar", arrowsize=14)
        style.configure("Horizontal.TScrollbar", arrowsize=14)

    def _bind_canvas_mousewheel(self, canvas: tk.Canvas) -> None:
        def _on_wheel(event):
            delta = event.delta
            if delta == 0:
                return
            step = -1 * int(delta / 120) if abs(delta) >= 120 else (-1 if delta > 0 else 1)
            canvas.yview_scroll(step, "units")

        def _on_linux_up(_event):
            canvas.yview_scroll(-1, "units")

        def _on_linux_down(_event):
            canvas.yview_scroll(1, "units")

        canvas.bind("<Enter>", lambda _e: canvas.focus_set())
        canvas.bind("<MouseWheel>", _on_wheel, add="+")
        canvas.bind("<Button-4>", _on_linux_up, add="+")
        canvas.bind("<Button-5>", _on_linux_down, add="+")

    def _bind_tree_mousewheel(self, tree: ttk.Treeview) -> None:
        def _on_wheel(event):
            delta = event.delta
            if delta == 0:
                return
            step = -1 * int(delta / 120) if abs(delta) >= 120 else (-1 if delta > 0 else 1)
            tree.yview_scroll(step, "units")

        def _on_shift_wheel(event):
            delta = event.delta
            if delta == 0:
                return
            step = -1 * int(delta / 120) if abs(delta) >= 120 else (-1 if delta > 0 else 1)
            tree.xview_scroll(step, "units")

        def _on_linux_up(_event):
            tree.yview_scroll(-1, "units")

        def _on_linux_down(_event):
            tree.yview_scroll(1, "units")

        tree.bind("<MouseWheel>", _on_wheel, add="+")
        tree.bind("<Shift-MouseWheel>", _on_shift_wheel, add="+")
        tree.bind("<Button-4>", _on_linux_up, add="+")
        tree.bind("<Button-5>", _on_linux_down, add="+")

    def _build_layout(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=10, pady=(10, 8))

        self.btn_toggle_pause = ttk.Button(top, text="⏸ Pause Scheduling", command=self._toggle_global_pause)
        self.btn_toggle_pause.pack(side=tk.LEFT)
        ttk.Button(top, text="▶ Start All Automation", command=lambda: self._set_all_automation(True)).pack(
            side=tk.LEFT, padx=(12, 0)
        )
        ttk.Button(top, text="⏸ Pause All Automation", command=lambda: self._set_all_automation(False)).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(top, text="Refresh", command=self.refresh_all).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Checkbutton(top, text="Auto refresh", variable=self.auto_refresh_var).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Button(top, text="Open Config", command=self._show_config_file_location).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Label(top, textvariable=self.status_text, style="Muted.TLabel").pack(side=tk.RIGHT)

        runtime_bar = ttk.Frame(self)
        runtime_bar.pack(fill=tk.X, padx=10, pady=(0, 8))
        ttk.Label(runtime_bar, textvariable=self.daemon_status_text).pack(side=tk.LEFT)
        ttk.Label(runtime_bar, textvariable=self.last_action_text, style="Muted.TLabel").pack(side=tk.RIGHT)

        body_split = ttk.PanedWindow(self, orient=tk.VERTICAL)
        body_split.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        top_section = ttk.Frame(body_split)
        bottom_section = ttk.Frame(body_split)
        body_split.add(top_section, weight=8)
        body_split.add(bottom_section, weight=3)

        main = ttk.PanedWindow(top_section, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(main)
        right = ttk.Frame(main)
        main.add(left, weight=9)
        main.add(right, weight=5)

        self._build_active_process_panel(left)
        self._build_config_panel(right)
        self._build_orphan_panel(bottom_section)

    def _build_active_process_panel(self, parent: ttk.Frame) -> None:
        wrapper = ttk.LabelFrame(parent, text="Active Codex / Claude Processes")
        wrapper.pack(fill=tk.BOTH, expand=True)

        columns = (
            "automate",
            "process_key",
            "type",
            "pid",
            "tty",
            "state",
            "runtime",
            "trigger",
            "timers",
            "agent_team",
            "new_chat",
            "progress",
            "args",
        )

        self.active_tree = ttk.Treeview(wrapper, columns=columns, show="headings", selectmode="browse")
        self.active_tree.heading("automate", text="Auto")
        self.active_tree.heading("process_key", text="Process Key")
        self.active_tree.heading("type", text="Type")
        self.active_tree.heading("pid", text="PID")
        self.active_tree.heading("tty", text="TTY")
        self.active_tree.heading("state", text="State")
        self.active_tree.heading("runtime", text="Runtime")
        self.active_tree.heading("trigger", text="Last Trigger")
        self.active_tree.heading("timers", text="Timers")
        self.active_tree.heading("agent_team", text="Agent Team")
        self.active_tree.heading("new_chat", text="New Chat On Done")
        self.active_tree.heading("progress", text="Signals")
        self.active_tree.heading("args", text="Command")

        self.active_tree.column("automate", width=64, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("process_key", width=180, anchor=tk.W, stretch=False)
        self.active_tree.column("type", width=86, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("pid", width=86, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("tty", width=104, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("state", width=90, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("runtime", width=130, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("trigger", width=180, anchor=tk.W, stretch=False)
        self.active_tree.column("timers", width=130, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("agent_team", width=110, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("new_chat", width=140, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("progress", width=110, anchor=tk.CENTER, stretch=False)
        self.active_tree.column("args", width=520, anchor=tk.W, stretch=True)

        y_scroll = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=self.active_tree.yview, style="Vertical.TScrollbar")
        x_scroll = ttk.Scrollbar(wrapper, orient=tk.HORIZONTAL, command=self.active_tree.xview, style="Horizontal.TScrollbar")
        self.active_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.active_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self._bind_tree_mousewheel(self.active_tree)

        self.active_tree.bind("<<TreeviewSelect>>", self._on_active_selected)

    def _build_config_panel(self, parent: ttk.Frame) -> None:
        wrapper = ttk.LabelFrame(parent, text="Per-Process Settings")
        wrapper.pack(fill=tk.BOTH, expand=True)
        scroll_host = ttk.Frame(wrapper)
        scroll_host.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(scroll_host, borderwidth=0, highlightthickness=0, background=BG_BASE)
        y_scroll = ttk.Scrollbar(scroll_host, orient=tk.VERTICAL, command=canvas.yview, style="Vertical.TScrollbar")
        canvas.configure(yscrollcommand=y_scroll.set)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        content = ttk.Frame(canvas)
        content_id = canvas.create_window((0, 0), window=content, anchor="nw")

        def _update_scroll_region(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _resize_content(_event=None):
            canvas.itemconfigure(content_id, width=canvas.winfo_width())

        content.bind("<Configure>", _update_scroll_region)
        canvas.bind("<Configure>", _resize_content)
        self._bind_canvas_mousewheel(canvas)

        ttk.Label(content, textvariable=self.selected_process_text).pack(anchor=tk.W, padx=12, pady=(12, 8))

        basic_frame = ttk.LabelFrame(content, text="Basic Controls")
        basic_frame.pack(fill=tk.X, padx=12, pady=(2, 8))
        ttk.Checkbutton(
            basic_frame,
            text="Enable agent team context",
            variable=self.enable_agent_team_var,
        ).pack(anchor=tk.W, padx=10, pady=(8, 4))
        ttk.Checkbutton(
            basic_frame,
            text="Start /new when task is done",
            variable=self.new_chat_on_done_var,
        ).pack(anchor=tk.W, padx=10, pady=(4, 8))

        types_frame = ttk.LabelFrame(content, text="Task Types & Weights")
        types_frame.pack(fill=tk.X, padx=12, pady=8)

        for option in TASK_TYPE_OPTIONS:
            row = ttk.Frame(types_frame)
            row.pack(fill=tk.X, padx=10, pady=3)
            cb = ttk.Checkbutton(
                row,
                text=option,
                variable=self.task_type_vars[option],
            )
            cb.pack(side=tk.LEFT, anchor=tk.W)
            ttk.Label(row, text="Weight", style="Muted.TLabel").pack(side=tk.RIGHT, padx=(8, 4))
            entry = ttk.Entry(row, textvariable=self.task_weight_vars[option], width=6, justify="center")
            entry.pack(side=tk.RIGHT)

        ttk.Separator(types_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=10, pady=(6, 4))
        ttk.Label(
            types_frame,
            textvariable=self.task_probability_text,
            justify=tk.LEFT,
            style="Muted.TLabel",
            wraplength=420,
        ).pack(fill=tk.X, padx=10, pady=(0, 8))

        task_frame = ttk.LabelFrame(content, text="Quota")
        task_frame.pack(fill=tk.X, padx=12, pady=(8, 6))
        inner_task_row = ttk.Frame(task_frame)
        inner_task_row.pack(fill=tk.X, padx=10, pady=8)
        ttk.Label(inner_task_row, text="Max Signals (0=unlimited):").pack(side=tk.LEFT)
        self.max_tasks_entry = ttk.Entry(inner_task_row, textvariable=self.max_tasks_var, width=10, justify="center")
        self.max_tasks_entry.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(inner_task_row, text="Reset Signals", command=self._reset_task_count).pack(side=tk.RIGHT)

        button_row = ttk.Frame(content)
        button_row.pack(fill=tk.X, padx=12, pady=(12, 8))

        self.btn_toggle_process_pause = ttk.Button(button_row, text="▶ Start Automation", command=self._toggle_process_pause)
        self.btn_toggle_process_pause.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(button_row, text="Save Selected", command=self._save_selected_config).pack(fill=tk.X, pady=3)
        ttk.Button(button_row, text="Reset to Default", command=self._reset_selected_to_default).pack(fill=tk.X, pady=3)

        help_text = (
            "Agent Team: controls whether daemon sends peer context for this process.\n"
            "Automate: if disabled, daemon will ignore this process.\n"
            "New Chat On Done: if enabled, daemon first asks Haiku to judge whether task is truly done, then decides '/new'.\n"
            "If disabled, daemon will block '/new' and continue in current chat.\n"
            "Task Types: daemon re-draws by weights on every automatic dispatch."
        )
        ttk.Label(content, text=help_text, justify=tk.LEFT, style="Muted.TLabel").pack(anchor=tk.W, padx=12, pady=(6, 12))

    def _build_orphan_panel(self, parent: tk.Widget) -> None:
        wrapper = ttk.LabelFrame(parent, text="Orphan Codex / Claude Processes")
        wrapper.pack(fill=tk.BOTH, expand=True, padx=0, pady=0, ipady=4)

        controls = ttk.Frame(wrapper)
        controls.pack(fill=tk.X, padx=8, pady=(6, 4))

        ttk.Button(controls, text="Scan Now", command=self.refresh_all).pack(side=tk.LEFT)
        ttk.Button(controls, text="Close Selected (TERM)", command=lambda: self._close_selected_orphans(False)).pack(
            side=tk.LEFT, padx=(8, 0)
        )
        ttk.Button(controls, text="Force Kill Selected (KILL)", command=lambda: self._close_selected_orphans(True)).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        columns = ("pid", "type", "tty", "ppid", "state", "args")
        self.orphan_tree = ttk.Treeview(wrapper, columns=columns, show="headings", selectmode="extended", height=7)

        self.orphan_tree.heading("pid", text="PID")
        self.orphan_tree.heading("type", text="Type")
        self.orphan_tree.heading("tty", text="TTY")
        self.orphan_tree.heading("ppid", text="PPID")
        self.orphan_tree.heading("state", text="State")
        self.orphan_tree.heading("args", text="Command")

        self.orphan_tree.column("pid", width=90, anchor=tk.CENTER, stretch=False)
        self.orphan_tree.column("type", width=90, anchor=tk.CENTER, stretch=False)
        self.orphan_tree.column("tty", width=100, anchor=tk.CENTER, stretch=False)
        self.orphan_tree.column("ppid", width=90, anchor=tk.CENTER, stretch=False)
        self.orphan_tree.column("state", width=100, anchor=tk.CENTER, stretch=False)
        self.orphan_tree.column("args", width=900, anchor=tk.W, stretch=True)

        y_scroll = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=self.orphan_tree.yview, style="Vertical.TScrollbar")
        x_scroll = ttk.Scrollbar(wrapper, orient=tk.HORIZONTAL, command=self.orphan_tree.xview, style="Horizontal.TScrollbar")
        self.orphan_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.orphan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0), pady=(0, 6))
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 8), pady=(0, 6))
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=(0, 6))
        self._bind_tree_mousewheel(self.orphan_tree)

    def _show_config_file_location(self) -> None:
        import subprocess
        subprocess.Popen(["open", self.config_path])

    def _auto_refresh_tick(self) -> None:
        if self.auto_refresh_var.get():
            self.refresh_all(update_inputs=False)
        self.after(REFRESH_INTERVAL_MS, self._auto_refresh_tick)

    def _set_action_text(self, text: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        self.last_action_text.set(f"{stamp} | {text}")

    def _update_task_probability_text(self) -> None:
        selected = []
        weighted = []
        total = 0.0

        for opt, enabled_var in self.task_type_vars.items():
            if not enabled_var.get():
                continue
            selected.append(opt)
            try:
                w = float(self.task_weight_vars[opt].get())
                if w < 0:
                    w = 0.0
            except (ValueError, TypeError):
                w = 0.0
            weighted.append((opt, w))
            total += w

        if not selected:
            self.task_probability_text.set("未选择任务类型：将按通用策略推进。")
            return

        if total <= 0:
            even = 100.0 / len(selected)
            parts = [f"{even:.1f}% 概率 {name}" for name in selected]
            self.task_probability_text.set("每次发放任务会重新抽签：当前权重总和为 0，按均匀概率分配。 " + "；".join(parts))
            return

        parts = [f"{(w / total) * 100:.1f}% 概率 {name}" for name, w in weighted]
        self.task_probability_text.set("每次发放任务会重新按权重抽签： " + "；".join(parts))

    def _mutate_config(self, mutator, action_text: str | None = None) -> bool:
        try:
            self.config_data = atomic_read_modify_write(mutator, self.config_path)
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Failed to update config: {exc}")
            return False
        if action_text:
            self._set_action_text(action_text)
        return True

    def _daemon_runtime(self) -> tuple[dict, bool]:
        daemon = self.runtime_status.get("daemon", {})
        if not isinstance(daemon, dict):
            return {}, False
        heartbeat_ts = daemon.get("heartbeat_ts", 0)
        poll_interval = daemon.get("poll_interval", 10)
        try:
            heartbeat_ts = float(heartbeat_ts)
        except (TypeError, ValueError):
            heartbeat_ts = 0.0
        try:
            poll_interval = int(poll_interval)
        except (TypeError, ValueError):
            poll_interval = 10
        staleness_window = max(45, poll_interval * 3)
        online = bool(daemon.get("running")) and heartbeat_ts > 0 and (time.time() - heartbeat_ts) <= staleness_window
        return daemon, online

    def _update_daemon_status_line(self, active_count: int) -> None:
        daemon, online = self._daemon_runtime()
        metrics = self.runtime_status.get("metrics", {})
        if not isinstance(metrics, dict):
            metrics = {}

        status = "ONLINE" if online else "OFFLINE"
        loop_count = int(metrics.get("loop_count", 0) or 0)
        decisions = int(metrics.get("decisions_made", 0) or 0)
        injected_ok = int(metrics.get("injections_succeeded", 0) or 0)
        injected_fail = int(metrics.get("injections_failed", 0) or 0)
        signals_sent = int(metrics.get("signals_sent", metrics.get("tasks_completed", 0)) or 0)
        pauses = int(metrics.get("pauses_triggered", 0) or 0)

        global_pause = bool(self.config_data.get("global_pause", False))
        pause_text = "PAUSED" if global_pause else "RUNNING"
        self.daemon_status_text.set(
            f"Daemon {status} | schedule={pause_text} | active={active_count} | loop={loop_count} | "
            f"decisions={decisions} | inject={injected_ok}/{injected_fail} | signals={signals_sent} | pauses={pauses}"
        )

    def _toggle_global_pause(self) -> None:
        holder = {"paused": False}

        def _toggle(cfg: dict) -> None:
            current = bool(cfg.get("global_pause", False))
            cfg["global_pause"] = not current
            holder["paused"] = cfg["global_pause"]

        if self._mutate_config(_toggle):
            self.global_pause_var.set(holder["paused"])
            self._set_action_text(f"{'Paused' if holder['paused'] else 'Resumed'} daemon scheduling")
            self._update_pause_button_state()
            self.refresh_all(update_inputs=False)

    def _update_pause_button_state(self) -> None:
        _, online = self._daemon_runtime()
        if self.config_data.get("global_pause", False):
            text = "▶ Resume Scheduling"
        else:
            text = "⏸ Pause Scheduling"
        if not online:
            text += " (daemon offline)"
        self.btn_toggle_pause.config(text=text)

    def refresh_all(self, update_inputs: bool = True) -> None:
        """3A: Run I/O (config load + process scan) in a background thread.
        Results are polled from the main thread — no cross-thread Tk calls."""
        if self._refresh_in_progress:
            return
        self._refresh_in_progress = True
        self._refresh_update_inputs = update_inputs

        def _background_io():
            try:
                config_data = load_process_config(self.config_path)
                runtime_status = load_runtime_status(self.runtime_path)
                active = find_active_agent_processes()
                orphans = find_orphan_agent_processes()
            except Exception:
                config_data = {"processes": {}, "global_pause": False}
                runtime_status = {"daemon": {}, "metrics": {}, "processes": {}}
                active = []
                orphans = []
            self._refresh_result = (config_data, runtime_status, active, orphans)

        threading.Thread(target=_background_io, daemon=True).start()
        self._poll_refresh_result()

    def _poll_refresh_result(self) -> None:
        """Poll for background thread results (called on main thread only)."""
        result = self._refresh_result
        if result is not None:
            self._refresh_result = None
            config_data, runtime_status, active, orphans = result
            self._apply_refresh_results(config_data, runtime_status, active, orphans, self._refresh_update_inputs)
        else:
            self.after(50, self._poll_refresh_result)

    def _apply_refresh_results(
        self,
        config_data: dict,
        runtime_status: dict,
        active: list,
        orphans: list,
        update_inputs: bool,
    ) -> None:
        """Apply refresh results on the main (Tk) thread."""
        self._refresh_in_progress = False

        # Unbind to prevent spurious selection events during update
        self.active_tree.unbind("<<TreeviewSelect>>")

        try:
            prev_selected_key = self.selected_process_key
            self.config_data = config_data
            self.runtime_status = runtime_status if isinstance(runtime_status, dict) else {"daemon": {}, "metrics": {}, "processes": {}}
            self._update_pause_button_state()

            self.active_by_key = {proc["process_key"]: proc for proc in active}
            self.orphan_by_pid = {proc["pid"]: proc for proc in orphans}

            self._render_active_tree(active)
            self._render_orphan_tree(orphans)

            if prev_selected_key and prev_selected_key in self.active_by_key:
                # Re-select the row to keep highlight
                if prev_selected_key in self.active_tree.get_children():
                    current_selection = self.active_tree.selection()
                    if not current_selection or current_selection[0] != prev_selected_key:
                        self.active_tree.selection_set(prev_selected_key)
                        self.active_tree.focus(prev_selected_key)

                    # Only update inputs if explicitly requested (manual refresh or selection change)
                    if update_inputs:
                        self._load_selected_config(prev_selected_key)
            else:
                self.selected_process_key = None
                self.selected_process_text.set("Selected: <none>")
                self._update_process_pause_btn_state()

            self._update_daemon_status_line(len(active))
            auto_enabled = 0
            for proc in active:
                cfg = get_effective_process_config(self.config_data, proc["process_key"])
                if cfg.get("automate_process", False):
                    auto_enabled += 1
            status_suffix = " [PAUSED]" if self.config_data.get("global_pause", False) else ""
            self.status_text.set(
                f"Config: {self.config_path} | active={len(active)} | auto={auto_enabled}/{len(active)} | orphan={len(orphans)}{status_suffix}"
            )
        finally:
            # Re-bind
            self.active_tree.bind("<<TreeviewSelect>>", self._on_active_selected)

    def _render_active_tree(self, processes: list[dict]) -> None:
        existing_iids = set(self.active_tree.get_children())
        seen_iids = set()
        runtime_processes = self.runtime_status.get("processes", {})
        if not isinstance(runtime_processes, dict):
            runtime_processes = {}
        self.active_tree.tag_configure("even", background="#ffffff")
        self.active_tree.tag_configure("odd", background="#f8fafc")
        self.active_tree.tag_configure("warn", foreground="#9a3412")
        self.active_tree.tag_configure("error", foreground="#b91c1c")

        for idx, proc in enumerate(processes):
            cfg = get_effective_process_config(self.config_data, proc["process_key"])
            max_tasks = cfg.get("max_tasks", 0)
            completed = cfg.get("completed_tasks", 0)
            session_completed = cfg.get("session_completed_tasks", 0)
            progress_str = f"S:{session_completed}/{max_tasks if max_tasks > 0 else '∞'} | All:{completed}"
            runtime = runtime_processes.get(proc["process_key"], {})
            if not isinstance(runtime, dict):
                runtime = {}
            runtime_state = runtime.get("status", "-")
            last_trigger = runtime.get("last_event", "-")
            cooldown_remaining = int(runtime.get("cooldown_remaining", 0) or 0)
            pause_remaining = int(runtime.get("pause_remaining", 0) or 0)
            stable_for = int(runtime.get("stable_for", 0) or 0)
            timer_parts = []
            if pause_remaining > 0:
                timer_parts.append(f"pause:{pause_remaining}s")
            if cooldown_remaining > 0:
                timer_parts.append(f"cd:{cooldown_remaining}s")
            if stable_for > 0 and runtime_state in {"waiting_stable", "idle"}:
                timer_parts.append(f"stable:{stable_for}s")
            timers = " | ".join(timer_parts) if timer_parts else "-"

            iid = proc["process_key"]
            seen_iids.add(iid)
            row_tags = ["even" if idx % 2 == 0 else "odd"]
            if runtime_state in {"paused", "paused_global", "cooldown"}:
                row_tags.append("warn")
            if runtime_state in {"inject_error", "decision_error", "terminal_error"}:
                row_tags.append("error")

            values = (
                "🟢" if cfg["automate_process"] else "⚪",
                proc["process_key"],
                proc["type"],
                proc["pid"],
                proc["tty"],
                proc["state"],
                runtime_state,
                last_trigger,
                timers,
                "on" if cfg["enable_agent_team"] else "off",
                "on" if cfg["new_chat_on_done"] else "off",
                progress_str,
                proc["args"],
            )

            if self.active_tree.exists(iid):
                self.active_tree.item(iid, values=values, tags=tuple(row_tags))
            else:
                self.active_tree.insert(
                    "",
                    tk.END,
                    iid=iid,
                    values=values,
                    tags=tuple(row_tags),
                )
        
        # Remove items that are no longer active
        for iid in existing_iids - seen_iids:
            self.active_tree.delete(iid)

    def _render_orphan_tree(self, processes: list[dict]) -> None:
        existing_iids = set(self.orphan_tree.get_children())
        seen_iids = set()
        self.orphan_tree.tag_configure("even", background="#ffffff")
        self.orphan_tree.tag_configure("odd", background="#f8fafc")

        for idx, proc in enumerate(processes):
            orphan_iid = f"orphan:{proc['pid']}"
            seen_iids.add(orphan_iid)
            tags = ("even",) if idx % 2 == 0 else ("odd",)
            
            values = (
                proc["pid"],
                proc["type"],
                proc["tty"],
                proc["ppid"],
                proc["state"],
                proc["args"],
            )

            if self.orphan_tree.exists(orphan_iid):
                self.orphan_tree.item(orphan_iid, values=values, tags=tags)
            else:
                self.orphan_tree.insert(
                    "",
                    tk.END,
                    iid=orphan_iid,
                    values=values,
                    tags=tags,
                )
        
        # Remove items that are no longer active
        for iid in existing_iids - seen_iids:
            self.orphan_tree.delete(iid)

    def _select_active_row(self, process_key: str) -> None:
        if process_key not in self.active_tree.get_children():
            return
        self.active_tree.selection_set(process_key)
        self.active_tree.focus(process_key)
        self.active_tree.see(process_key)
        self._load_selected_config(process_key)

    def _on_active_selected(self, _event=None) -> None:
        selected = self.active_tree.selection()
        if not selected:
            self.selected_process_key = None
            self.selected_process_text.set("Selected: <none>")
            return
        process_key = selected[0]
        self._load_selected_config(process_key)

    def _load_selected_config(self, process_key: str) -> None:
        self.selected_process_key = process_key
        proc = self.active_by_key.get(process_key)
        if proc:
            self.selected_process_text.set(
                f"Selected: {process_key} (PID={proc['pid']} TTY={proc['tty']})"
            )
        else:
            self.selected_process_text.set(f"Selected: {process_key}")

        cfg = get_effective_process_config(self.config_data, process_key)
        self.enable_agent_team_var.set(cfg["enable_agent_team"])
        self.automate_process_var.set(cfg["automate_process"])
        self.new_chat_on_done_var.set(cfg["new_chat_on_done"])

        current_types = set(cfg.get("task_types", []))
        current_weights = cfg.get("task_weights", {})
        
        for option, var in self.task_type_vars.items():
            var.set(option in current_types)
            
            # Load weight, default to 10
            weight = current_weights.get(option, 10)
            self.task_weight_vars[option].set(str(weight))

        # Only update text entry if it doesn't have focus (user might be typing)
        # This prevents the refresh loop from overwriting user input
        try:
            if self.focus_get() != self.max_tasks_entry:
                self.max_tasks_var.set(str(cfg.get("max_tasks", 0)))
        except Exception:
            self.max_tasks_var.set(str(cfg.get("max_tasks", 0)))

        self._update_task_probability_text()
        self._update_process_pause_btn_state()

    def _update_process_pause_btn_state(self) -> None:
        if not self.selected_process_key:
            self.btn_toggle_process_pause.config(state=tk.DISABLED, text="▶ Start Automation")
            return
            
        self.btn_toggle_process_pause.config(state=tk.NORMAL)
        if self.automate_process_var.get():
            self.btn_toggle_process_pause.config(text="⏸ Pause Automation")
        else:
            self.btn_toggle_process_pause.config(text="▶ Start Automation")

    def _toggle_process_pause(self) -> None:
        if not self.selected_process_key:
            return
            
        current = self.automate_process_var.get()
        self.automate_process_var.set(not current)
        self._update_process_pause_btn_state()
        
        # Auto-save when toggled
        self._save_selected_config()

    def _set_all_automation(self, enabled: bool) -> None:
        active_keys = list(self.active_by_key.keys())
        if not active_keys:
            messagebox.showwarning("No active process", "No active Codex/Claude process found.")
            return

        def _update(cfg: dict) -> None:
            processes = cfg.setdefault("processes", {})
            for key in active_keys:
                current = get_effective_process_config(cfg, key)
                current["automate_process"] = enabled
                processes[key] = current

        label = "Started" if enabled else "Paused"
        if self._mutate_config(_update, action_text=f"{label} automation for {len(active_keys)} active process(es)"):
            if self.selected_process_key in active_keys:
                self.automate_process_var.set(enabled)
                self._update_process_pause_btn_state()
            self.refresh_all(update_inputs=False)

    def _save_selected_config(self) -> None:
        if not self.selected_process_key:
            messagebox.showwarning("No selection", "Please select an active process first.")
            return

        try:
            max_tasks_val = int(self.max_tasks_var.get())
            if max_tasks_val < 0:
                raise ValueError("Cannot be negative")
        except ValueError:
            messagebox.showerror("Invalid Input", "Max Signals must be a non-negative integer.")
            return

        # Preserve existing completed_tasks count
        existing_cfg = self.config_data.get("processes", {}).get(self.selected_process_key, {})
        current_completed = existing_cfg.get("completed_tasks", 0)
        current_session_completed = existing_cfg.get("session_completed_tasks", 0)

        selected_types = []
        task_weights = {}
        
        for opt, var in self.task_type_vars.items():
            if var.get():
                selected_types.append(opt)
                # Parse weight
                try:
                    w_val = int(self.task_weight_vars[opt].get())
                    if w_val < 0: w_val = 0
                except ValueError:
                    w_val = 10
                task_weights[opt] = w_val

        process_key = self.selected_process_key

        def _update(cfg: dict) -> None:
            processes = cfg.setdefault("processes", {})
            existing_cfg = get_effective_process_config(cfg, process_key)
            processes[process_key] = {
                "enable_agent_team": self.enable_agent_team_var.get(),
                "automate_process": self.automate_process_var.get(),
                "new_chat_on_done": self.new_chat_on_done_var.get(),
                "max_tasks": max_tasks_val,
                "completed_tasks": existing_cfg.get("completed_tasks", current_completed),
                "session_completed_tasks": existing_cfg.get("session_completed_tasks", current_session_completed),
                "task_types": selected_types,
                "task_weights": task_weights,
            }

        if self._mutate_config(_update, action_text=f"Saved settings for {process_key}"):
            self.refresh_all(update_inputs=False)

    def _reset_task_count(self) -> None:
        if not self.selected_process_key:
            messagebox.showwarning("No selection", "Please select an active process first.")
            return
            
        if messagebox.askyesno("Confirm", "Reset SESSION signal count to 0?"):
            process_key = self.selected_process_key

            def _update(cfg: dict) -> None:
                processes = cfg.setdefault("processes", {})
                current = get_effective_process_config(cfg, process_key)
                current["session_completed_tasks"] = 0
                processes[process_key] = current

            if self._mutate_config(_update, action_text=f"Reset session signal count for {process_key}"):
                self.refresh_all(update_inputs=False)

    def _reset_selected_to_default(self) -> None:
        if not self.selected_process_key:
            messagebox.showwarning("No selection", "Please select an active process first.")
            return

        self.enable_agent_team_var.set(DEFAULT_PROCESS_CONFIG["enable_agent_team"])
        self.automate_process_var.set(DEFAULT_PROCESS_CONFIG["automate_process"])
        self.new_chat_on_done_var.set(DEFAULT_PROCESS_CONFIG["new_chat_on_done"])
        self.max_tasks_var.set(str(DEFAULT_PROCESS_CONFIG["max_tasks"]))
        
        for var in self.task_type_vars.values():
            var.set(False)
        for var in self.task_weight_vars.values():
            var.set("10")

        process_key = self.selected_process_key

        def _update(cfg: dict) -> None:
            processes = cfg.setdefault("processes", {})
            current = get_effective_process_config(cfg, process_key)
            new_cfg = DEFAULT_PROCESS_CONFIG.copy()
            new_cfg["completed_tasks"] = current.get("completed_tasks", 0)
            new_cfg["session_completed_tasks"] = current.get("session_completed_tasks", 0)
            processes[process_key] = new_cfg

        if self._mutate_config(_update, action_text=f"Reset settings to default for {process_key}"):
            self.refresh_all(update_inputs=False)

    def _close_selected_orphans(self, force: bool) -> None:
        selected = self.orphan_tree.selection()
        if not selected:
            messagebox.showwarning("No selection", "Please select one or more orphan processes.")
            return

        pids = []
        for iid in selected:
            values = self.orphan_tree.item(iid, "values")
            if not values:
                continue
            try:
                pids.append(int(values[0]))
            except (TypeError, ValueError):
                continue

        if not pids:
            messagebox.showwarning("No PID", "No valid PID was selected.")
            return

        action = "SIGKILL" if force else "SIGTERM"
        if not messagebox.askyesno(
            "Confirm",
            f"Send {action} to {len(pids)} process(es)?",
        ):
            return

        # Run termination in background to avoid blocking GUI
        threading.Thread(
            target=self._close_orphans_background,
            args=(pids, force),
            daemon=True
        ).start()

    def _close_orphans_background(self, pids: list[int], force: bool) -> None:
        ok_count = 0
        failures = []

        for pid in pids:
            ok, detail = terminate_process(pid, force=force)
            if ok:
                ok_count += 1
            else:
                failures.append(f"{pid}: {detail}")

        # Schedule result handling on main thread
        self.after(0, lambda: self._on_close_orphans_complete(ok_count, len(pids), failures))

    def _on_close_orphans_complete(self, ok_count: int, total_count: int, failures: list[str]) -> None:
        self.refresh_all()

        if failures:
            detail_text = "\n".join(failures)
            messagebox.showwarning(
                "Partial Result",
                f"Succeeded: {ok_count}/{total_count}\nFailed:\n{detail_text}",
            )
        else:
            messagebox.showinfo("Done", f"Succeeded: {ok_count}/{total_count}")


def main() -> None:
    app = TermiteControlGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
