#!/usr/bin/env python3
"""GUI controller for per-process Termite automation settings."""

from __future__ import annotations

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

        self.auto_refresh_var = tk.BooleanVar(value=True)
        self.enable_agent_team_var = tk.BooleanVar(value=DEFAULT_PROCESS_CONFIG["enable_agent_team"])
        self.automate_process_var = tk.BooleanVar(value=DEFAULT_PROCESS_CONFIG["automate_process"])
        self.new_chat_on_done_var = tk.BooleanVar(value=DEFAULT_PROCESS_CONFIG["new_chat_on_done"])

        self.selected_process_text = tk.StringVar(value="Selected: <none>")
        self.status_text = tk.StringVar(value=f"Config file: {self.config_path}")
        self.global_pause_var = tk.BooleanVar(value=False)

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
        self.active_tree.heading("args", text="Command")

        self.active_tree.column("automate", width=60, anchor=tk.CENTER)
        self.active_tree.column("process_key", width=170, anchor=tk.W)
        self.active_tree.column("type", width=80, anchor=tk.CENTER)
        self.active_tree.column("pid", width=80, anchor=tk.CENTER)
        self.active_tree.column("tty", width=100, anchor=tk.CENTER)
        self.active_tree.column("state", width=80, anchor=tk.CENTER)
        self.active_tree.column("agent_team", width=100, anchor=tk.CENTER)
        self.active_tree.column("new_chat", width=130, anchor=tk.CENTER)
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
            self.refresh_all()
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

    def refresh_all(self) -> None:
        prev_selected_key = self.selected_process_key
        self.config_data = load_process_config(self.config_path)
        self._update_pause_button_state()

        active = find_active_agent_processes()
        orphans = find_orphan_agent_processes()

        self.active_by_key = {proc["process_key"]: proc for proc in active}
        self.orphan_by_pid = {proc["pid"]: proc for proc in orphans}

        self._render_active_tree(active)
        self._render_orphan_tree(orphans)

        if prev_selected_key and prev_selected_key in self.active_by_key:
            self._select_active_row(prev_selected_key)
        else:
            self.selected_process_key = None
            self.selected_process_text.set("Selected: <none>")
            self._update_process_pause_btn_state()

        status_suffix = " [PAUSED]" if self.config_data.get("global_pause", False) else ""
        self.status_text.set(
            f"Config file: {self.config_path} | active={len(active)} | orphan={len(orphans)}{status_suffix}"
        )

    def _render_active_tree(self, processes: list[dict]) -> None:
        for item in self.active_tree.get_children():
            self.active_tree.delete(item)

        for proc in processes:
            cfg = get_effective_process_config(self.config_data, proc["process_key"])
            self.active_tree.insert(
                "",
                tk.END,
                iid=proc["process_key"],
                values=(
                    "🟢" if cfg["automate_process"] else "⚪",
                    proc["process_key"],
                    proc["type"],
                    proc["pid"],
                    proc["tty"],
                    proc["state"],
                    "on" if cfg["enable_agent_team"] else "off",
                    "on" if cfg["new_chat_on_done"] else "off",
                    proc["args"],
                ),
            )

    def _render_orphan_tree(self, processes: list[dict]) -> None:
        for item in self.orphan_tree.get_children():
            self.orphan_tree.delete(item)

        for proc in processes:
            orphan_iid = f"orphan:{proc['pid']}"
            self.orphan_tree.insert(
                "",
                tk.END,
                iid=orphan_iid,
                values=(
                    proc["pid"],
                    proc["type"],
                    proc["tty"],
                    proc["ppid"],
                    proc["state"],
                    proc["args"],
                ),
            )

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

        processes = self.config_data.setdefault("processes", {})
        processes[self.selected_process_key] = {
            "enable_agent_team": self.enable_agent_team_var.get(),
            "automate_process": self.automate_process_var.get(),
            "new_chat_on_done": self.new_chat_on_done_var.get(),
        }

        try:
            save_process_config(self.config_data, self.config_path)
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Failed to save config: {exc}")
            return

        self.refresh_all()
        messagebox.showinfo("Saved", f"Saved config for {self.selected_process_key}.")

    def _reset_selected_to_default(self) -> None:
        if not self.selected_process_key:
            messagebox.showwarning("No selection", "Please select an active process first.")
            return

        self.enable_agent_team_var.set(DEFAULT_PROCESS_CONFIG["enable_agent_team"])
        self.automate_process_var.set(DEFAULT_PROCESS_CONFIG["automate_process"])
        self.new_chat_on_done_var.set(DEFAULT_PROCESS_CONFIG["new_chat_on_done"])

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
