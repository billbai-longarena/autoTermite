#!/usr/bin/env python3
"""GUI controller for per-process Termite automation settings."""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

from termite_process_utils import (
    CONFIG_FILE,
    DEFAULT_PROCESS_CONFIG,
    find_active_agent_processes,
    find_orphan_agent_processes,
    get_effective_process_config,
    load_process_config,
    save_process_config,
    terminate_process,
)

REFRESH_INTERVAL_MS = 3000

TASK_TYPE_OPTIONS = [
    "审计",
    "基于网络的客户需求研究和市场研究并形成开发需求",
    "AB测试和转化漏斗设计",
    "自主根据任务优先级选择",
    "你是自由的",
]


class TermiteControlGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Termite Process Control")
        self.geometry("1400x820")
        self.minsize(1150, 700)

        self.config_path = CONFIG_FILE
        self.config_data = {"processes": {}, "global_pause": False}

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
        self.global_pause_var = tk.BooleanVar(value=False)

        self.task_type_vars = {}
        self.task_weight_vars = {}
        for option in TASK_TYPE_OPTIONS:
            self.task_type_vars[option] = tk.BooleanVar(value=False)
            self.task_weight_vars[option] = tk.StringVar(value="10")

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
                # Run pkill with elevated privileges using osascript to show macOS native password/Touch ID prompt
                script = 'do shell script "pkill -f termite_daemon.py" with administrator privileges'
                subprocess.run(["osascript", "-e", script], check=False)
                messagebox.showinfo("Exit", "Background daemon stopped. Exiting GUI.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop daemon: {e}")
                
        # Both Yes and No will eventually reach here
        self.destroy()

    def _build_layout(self) -> None:
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=10, pady=(10, 8))

        self.btn_toggle_pause = ttk.Button(top, text="⏸ Pause Daemon", command=self._toggle_global_pause)
        self.btn_toggle_pause.pack(side=tk.LEFT)
        
        ttk.Button(top, text="Refresh", command=self.refresh_all).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Checkbutton(top, text="Auto refresh", variable=self.auto_refresh_var).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Button(top, text="Open Config", command=self._show_config_file_location).pack(side=tk.LEFT, padx=(12, 0))
        ttk.Label(top, textvariable=self.status_text).pack(side=tk.RIGHT)

        main = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        left = ttk.Frame(main)
        right = ttk.Frame(main)
        main.add(left, weight=7)
        main.add(right, weight=3)

        self._build_active_process_panel(left)
        self._build_config_panel(right)
        self._build_orphan_panel(self)

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
        self.active_tree.heading("agent_team", text="Agent Team")
        self.active_tree.heading("new_chat", text="New Chat On Done")
        self.active_tree.heading("progress", text="Progress")
        self.active_tree.heading("args", text="Command")

        self.active_tree.column("automate", width=60, anchor=tk.CENTER)
        self.active_tree.column("process_key", width=170, anchor=tk.W)
        self.active_tree.column("type", width=80, anchor=tk.CENTER)
        self.active_tree.column("pid", width=80, anchor=tk.CENTER)
        self.active_tree.column("tty", width=100, anchor=tk.CENTER)
        self.active_tree.column("state", width=80, anchor=tk.CENTER)
        self.active_tree.column("agent_team", width=100, anchor=tk.CENTER)
        self.active_tree.column("new_chat", width=130, anchor=tk.CENTER)
        self.active_tree.column("progress", width=100, anchor=tk.CENTER)
        self.active_tree.column("args", width=480, anchor=tk.W)

        y_scroll = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=self.active_tree.yview)
        x_scroll = ttk.Scrollbar(wrapper, orient=tk.HORIZONTAL, command=self.active_tree.xview)
        self.active_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.active_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)

        self.active_tree.bind("<<TreeviewSelect>>", self._on_active_selected)

    def _build_config_panel(self, parent: ttk.Frame) -> None:
        wrapper = ttk.LabelFrame(parent, text="Per-Process Settings")
        wrapper.pack(fill=tk.BOTH, expand=True)

        ttk.Label(wrapper, textvariable=self.selected_process_text).pack(anchor=tk.W, padx=12, pady=(12, 8))

        ttk.Checkbutton(
            wrapper,
            text="Enable agent team context",
            variable=self.enable_agent_team_var,
        ).pack(anchor=tk.W, padx=12, pady=4)

        ttk.Checkbutton(
            wrapper,
            text="Start /new when task is done",
            variable=self.new_chat_on_done_var,
        ).pack(anchor=tk.W, padx=12, pady=4)

        # Task Types Section
        types_frame = ttk.LabelFrame(wrapper, text="Task Types & Weights")
        types_frame.pack(fill=tk.X, padx=12, pady=8)
        
        for option in TASK_TYPE_OPTIONS:
            row = ttk.Frame(types_frame)
            row.pack(fill=tk.X, padx=8, pady=2)
            
            cb = ttk.Checkbutton(
                row,
                text=option,
                variable=self.task_type_vars[option],
            )
            cb.pack(side=tk.LEFT, anchor=tk.W)
            
            # Weight entry
            ttk.Label(row, text="Wt:").pack(side=tk.RIGHT, padx=(4, 0))
            entry = ttk.Entry(row, textvariable=self.task_weight_vars[option], width=4)
            entry.pack(side=tk.RIGHT)

        task_frame = ttk.Frame(wrapper)
        task_frame.pack(fill=tk.X, padx=12, pady=4)
        ttk.Label(task_frame, text="Max Tasks (0=unlimited):").pack(side=tk.LEFT)
        self.max_tasks_entry = ttk.Entry(task_frame, textvariable=self.max_tasks_var, width=10)
        self.max_tasks_entry.pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(task_frame, text="Reset Count", command=self._reset_task_count).pack(side=tk.LEFT, padx=(12, 0))

        button_row = ttk.Frame(wrapper)
        button_row.pack(fill=tk.X, padx=12, pady=(14, 8))

        self.btn_toggle_process_pause = ttk.Button(button_row, text="▶ Start Automation", command=self._toggle_process_pause)
        self.btn_toggle_process_pause.pack(side=tk.LEFT)
        ttk.Button(button_row, text="Save Selected", command=self._save_selected_config).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(button_row, text="Reset to Default", command=self._reset_selected_to_default).pack(
            side=tk.LEFT, padx=(8, 0)
        )

        help_text = (
            "Agent Team: controls whether daemon sends peer context for this process.\n"
            "Automate: if disabled, daemon will ignore this process.\n"
            "New Chat On Done: if disabled, daemon will block '/new' and continue in current chat."
        )
        ttk.Label(wrapper, text=help_text, justify=tk.LEFT).pack(anchor=tk.W, padx=12, pady=(8, 12))

    def _build_orphan_panel(self, parent: tk.Widget) -> None:
        wrapper = ttk.LabelFrame(parent, text="Orphan Codex / Claude Processes")
        wrapper.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 10), ipady=4)

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

        self.orphan_tree.column("pid", width=90, anchor=tk.CENTER)
        self.orphan_tree.column("type", width=80, anchor=tk.CENTER)
        self.orphan_tree.column("tty", width=90, anchor=tk.CENTER)
        self.orphan_tree.column("ppid", width=90, anchor=tk.CENTER)
        self.orphan_tree.column("state", width=90, anchor=tk.CENTER)
        self.orphan_tree.column("args", width=900, anchor=tk.W)

        y_scroll = ttk.Scrollbar(wrapper, orient=tk.VERTICAL, command=self.orphan_tree.yview)
        x_scroll = ttk.Scrollbar(wrapper, orient=tk.HORIZONTAL, command=self.orphan_tree.xview)
        self.orphan_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.orphan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8, 0), pady=(0, 6))
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 8), pady=(0, 6))
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=(0, 6))

    def _show_config_file_location(self) -> None:
        messagebox.showinfo("Config Path", self.config_path)

    def _auto_refresh_tick(self) -> None:
        if self.auto_refresh_var.get():
            self.refresh_all(update_inputs=False)
        self.after(REFRESH_INTERVAL_MS, self._auto_refresh_tick)

    def _toggle_global_pause(self) -> None:
        current_pause = self.config_data.get("global_pause", False)
        new_pause = not current_pause
        self.config_data["global_pause"] = new_pause
        
        try:
            save_process_config(self.config_data, self.config_path)
            self._update_pause_button_state()
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Failed to save global pause state: {exc}")

    def _update_pause_button_state(self) -> None:
        if self.config_data.get("global_pause", False):
            self.btn_toggle_pause.config(text="▶ Resume Daemon")
            self.status_text.set(f"Config file: {self.config_path} | STATUS: PAUSED")
        else:
            self.btn_toggle_pause.config(text="⏸ Pause Daemon")

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
                active = find_active_agent_processes()
                orphans = find_orphan_agent_processes()
            except Exception:
                config_data = {"processes": {}, "global_pause": False}
                active = []
                orphans = []
            self._refresh_result = (config_data, active, orphans)

        threading.Thread(target=_background_io, daemon=True).start()
        self._poll_refresh_result()

    def _poll_refresh_result(self) -> None:
        """Poll for background thread results (called on main thread only)."""
        result = self._refresh_result
        if result is not None:
            self._refresh_result = None
            config_data, active, orphans = result
            self._apply_refresh_results(config_data, active, orphans, self._refresh_update_inputs)
        else:
            self.after(50, self._poll_refresh_result)

    def _apply_refresh_results(self, config_data: dict, active: list, orphans: list, update_inputs: bool) -> None:
        """Apply refresh results on the main (Tk) thread."""
        self._refresh_in_progress = False

        # Unbind to prevent spurious selection events during update
        self.active_tree.unbind("<<TreeviewSelect>>")

        try:
            prev_selected_key = self.selected_process_key
            self.config_data = config_data
            self._update_pause_button_state()

            self.active_by_key = {proc["process_key"]: proc for proc in active}
            self.orphan_by_pid = {proc["pid"]: proc for proc in orphans}

            self._render_active_tree(active)
            self._render_orphan_tree(orphans)

            if prev_selected_key and prev_selected_key in self.active_by_key:
                # Re-select the row to keep highlight
                if prev_selected_key not in self.active_tree.get_children():
                    return

                # Check if selection is already correct to avoid triggering event unnecessarily
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

            status_suffix = " [PAUSED]" if self.config_data.get("global_pause", False) else ""
            self.status_text.set(
                f"Config file: {self.config_path} | active={len(active)} | orphan={len(orphans)}{status_suffix}"
            )
        finally:
            # Re-bind
            self.active_tree.bind("<<TreeviewSelect>>", self._on_active_selected)

    def _render_active_tree(self, processes: list[dict]) -> None:
        existing_iids = set(self.active_tree.get_children())
        seen_iids = set()

        for proc in processes:
            cfg = get_effective_process_config(self.config_data, proc["process_key"])
            max_tasks = cfg.get("max_tasks", 0)
            completed = cfg.get("completed_tasks", 0)
            session_completed = cfg.get("session_completed_tasks", 0)
            progress_str = f"S:{session_completed}/{max_tasks if max_tasks > 0 else '∞'} | T:{completed}"
            
            iid = proc["process_key"]
            seen_iids.add(iid)
            
            values = (
                "🟢" if cfg["automate_process"] else "⚪",
                proc["process_key"],
                proc["type"],
                proc["pid"],
                proc["tty"],
                proc["state"],
                "on" if cfg["enable_agent_team"] else "off",
                "on" if cfg["new_chat_on_done"] else "off",
                progress_str,
                proc["args"],
            )

            if self.active_tree.exists(iid):
                self.active_tree.item(iid, values=values)
            else:
                self.active_tree.insert(
                    "",
                    tk.END,
                    iid=iid,
                    values=values,
                )
        
        # Remove items that are no longer active
        for iid in existing_iids - seen_iids:
            self.active_tree.delete(iid)

    def _render_orphan_tree(self, processes: list[dict]) -> None:
        existing_iids = set(self.orphan_tree.get_children())
        seen_iids = set()

        for proc in processes:
            orphan_iid = f"orphan:{proc['pid']}"
            seen_iids.add(orphan_iid)
            
            values = (
                proc["pid"],
                proc["type"],
                proc["tty"],
                proc["ppid"],
                proc["state"],
                proc["args"],
            )

            if self.orphan_tree.exists(orphan_iid):
                self.orphan_tree.item(orphan_iid, values=values)
            else:
                self.orphan_tree.insert(
                    "",
                    tk.END,
                    iid=orphan_iid,
                    values=values,
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

    def _save_selected_config(self) -> None:
        if not self.selected_process_key:
            messagebox.showwarning("No selection", "Please select an active process first.")
            return

        try:
            max_tasks_val = int(self.max_tasks_var.get())
            if max_tasks_val < 0:
                raise ValueError("Cannot be negative")
        except ValueError:
            messagebox.showerror("Invalid Input", "Max Tasks must be a non-negative integer.")
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

        processes = self.config_data.setdefault("processes", {})
        processes[self.selected_process_key] = {
            "enable_agent_team": self.enable_agent_team_var.get(),
            "automate_process": self.automate_process_var.get(),
            "new_chat_on_done": self.new_chat_on_done_var.get(),
            "max_tasks": max_tasks_val,
            "completed_tasks": current_completed,
            "session_completed_tasks": current_session_completed,
            "task_types": selected_types,
            "task_weights": task_weights,
        }

        try:
            save_process_config(self.config_data, self.config_path)
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Failed to save config: {exc}")
            return

        self.refresh_all()
        messagebox.showinfo("Saved", f"Saved config for {self.selected_process_key}.")

    def _reset_task_count(self) -> None:
        if not self.selected_process_key:
            messagebox.showwarning("No selection", "Please select an active process first.")
            return
            
        if messagebox.askyesno("Confirm", "Reset SESSION task count to 0?"):
            processes = self.config_data.setdefault("processes", {})
            if self.selected_process_key in processes:
                processes[self.selected_process_key]["session_completed_tasks"] = 0
                try:
                    save_process_config(self.config_data, self.config_path)
                    self.refresh_all()
                except Exception as exc:
                    messagebox.showerror("Save Failed", f"Failed to save: {exc}")

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

        processes = self.config_data.setdefault("processes", {})
        processes[self.selected_process_key] = DEFAULT_PROCESS_CONFIG.copy()

        try:
            save_process_config(self.config_data, self.config_path)
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Failed to reset config: {exc}")
            return

        self.refresh_all()

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

        ok_count = 0
        failures = []

        for pid in pids:
            ok, detail = terminate_process(pid, force=force)
            if ok:
                ok_count += 1
            else:
                failures.append(f"{pid}: {detail}")

        self.refresh_all()

        if failures:
            detail_text = "\n".join(failures)
            messagebox.showwarning(
                "Partial Result",
                f"Succeeded: {ok_count}/{len(pids)}\nFailed:\n{detail_text}",
            )
        else:
            messagebox.showinfo("Done", f"Succeeded: {ok_count}/{len(pids)}")


def main() -> None:
    app = TermiteControlGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
