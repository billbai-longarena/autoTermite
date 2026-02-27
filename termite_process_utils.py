#!/usr/bin/env python3
"""Utilities for detecting Codex/Claude processes and storing per-process config."""

from __future__ import annotations

import fcntl
import json
import os
import signal
import subprocess
import tempfile
import time
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple

CONFIG_FILE = "termite_process_config.json"

DEFAULT_PROCESS_CONFIG = {
    "enable_agent_team": True,
    "automate_process": False,
    "new_chat_on_done": True,
    "max_tasks": 0,  # 0 means unlimited
    "completed_tasks": 0,
    "session_completed_tasks": 0,
    "task_types": [],  # List of selected task types
    "task_weights": {}, # Dictionary of task type -> weight (int/float)
}


def _safe_int(value, default: int) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def _safe_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _atomic_write_json(path: str, data: dict) -> None:
    """Write JSON atomically via temp file + os.replace (POSIX atomic on same FS)."""
    dir_name = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


@contextmanager
def _file_lock(path: str, exclusive: bool = False):
    """Acquire an advisory file lock (shared for reads, exclusive for writes)."""
    lock_path = path + ".lock"
    lock_fd = open(lock_path, "a")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


def normalize_process_config(raw: Optional[dict]) -> dict:
    raw = raw or {}
    return {
        "enable_agent_team": _safe_bool(
            raw.get("enable_agent_team"), DEFAULT_PROCESS_CONFIG["enable_agent_team"]
        ),
        "automate_process": _safe_bool(
            raw.get("automate_process"), DEFAULT_PROCESS_CONFIG["automate_process"]
        ),
        "new_chat_on_done": _safe_bool(
            raw.get("new_chat_on_done"), DEFAULT_PROCESS_CONFIG["new_chat_on_done"]
        ),
        "max_tasks": _safe_int(
            raw.get("max_tasks"), DEFAULT_PROCESS_CONFIG["max_tasks"]
        ),
        "completed_tasks": _safe_int(
            raw.get("completed_tasks"), DEFAULT_PROCESS_CONFIG["completed_tasks"]
        ),
        "session_completed_tasks": _safe_int(
            raw.get("session_completed_tasks"), DEFAULT_PROCESS_CONFIG["session_completed_tasks"]
        ),
        "task_types": raw.get("task_types")
        if isinstance(raw.get("task_types"), list)
        else DEFAULT_PROCESS_CONFIG["task_types"],
        "task_weights": raw.get("task_weights")
        if isinstance(raw.get("task_weights"), dict)
        else DEFAULT_PROCESS_CONFIG["task_weights"],
    }


def _load_process_config_impl(path: str) -> dict:
    """Internal: read and parse config. Caller must hold lock."""
    if not os.path.exists(path):
        return {"processes": {}, "global_pause": False, "daemon_settings": {}}

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"processes": {}, "global_pause": False, "daemon_settings": {}}

    processes = data.get("processes")
    if not isinstance(processes, dict):
        processes = {}

    normalized = {}
    for process_key, process_cfg in processes.items():
        normalized[str(process_key)] = normalize_process_config(process_cfg)

    global_pause = _safe_bool(data.get("global_pause"), False)

    daemon_settings = data.get("daemon_settings")
    if not isinstance(daemon_settings, dict):
        daemon_settings = {}

    return {"processes": normalized, "global_pause": global_pause, "daemon_settings": daemon_settings}


def load_process_config(path: str = CONFIG_FILE) -> dict:
    with _file_lock(path, exclusive=False):
        return _load_process_config_impl(path)


def _save_process_config_impl(config: dict, path: str) -> None:
    """Internal: serialize and write config. Caller must hold lock."""
    serializable = {
        "processes": {},
        "global_pause": _safe_bool(config.get("global_pause"), False)
    }
    processes = config.get("processes") if isinstance(config, dict) else {}
    if isinstance(processes, dict):
        for process_key, process_cfg in processes.items():
            serializable["processes"][str(process_key)] = normalize_process_config(process_cfg)

    daemon_settings = config.get("daemon_settings")
    if isinstance(daemon_settings, dict):
        serializable["daemon_settings"] = daemon_settings

    _atomic_write_json(path, serializable)


def save_process_config(config: dict, path: str = CONFIG_FILE) -> None:
    with _file_lock(path, exclusive=True):
        _save_process_config_impl(config, path)


def atomic_read_modify_write(modifier_fn, path: str = CONFIG_FILE) -> dict:
    """Atomically read, modify, and write config under a single exclusive lock.

    *modifier_fn(config)* is called with the current config dict; it should
    mutate it in place.  Returns the modified config.
    """
    with _file_lock(path, exclusive=True):
        config = _load_process_config_impl(path)
        modifier_fn(config)
        _save_process_config_impl(config, path)
        return config


def get_effective_process_config(config: dict, process_key: str) -> dict:
    if not isinstance(config, dict):
        return DEFAULT_PROCESS_CONFIG.copy()
    processes = config.get("processes")
    if not isinstance(processes, dict):
        return DEFAULT_PROCESS_CONFIG.copy()
    raw = processes.get(process_key)
    return normalize_process_config(raw)


def classify_agent_type(args: str) -> Optional[str]:
    args_lower = args.lower()

    if "termite_daemon" in args_lower or "termite_control_gui" in args_lower:
        return None

    if "python" in args_lower and "codex_daemon" in args_lower:
        return None

    if "codex" in args_lower:
        return "codex"

    if "claude" in args_lower:
        return "claude"

    return None


def build_process_key(agent_type: str, tty: str, pid: int) -> str:
    if tty and tty != "??":
        return f"{agent_type}:{tty}"
    return f"{agent_type}:pid:{pid}"


def scan_target_processes() -> List[dict]:
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,ppid,tty,state,args"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return []

    my_pid = str(os.getpid())
    rows = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue

        pid_str, ppid_str, tty, state, args = parts
        if pid_str == my_pid:
            continue

        agent_type = classify_agent_type(args)
        if not agent_type:
            continue

        try:
            pid = int(pid_str)
            ppid = int(ppid_str)
        except ValueError:
            continue

        rows.append(
            {
                "pid": pid,
                "ppid": ppid,
                "tty": tty,
                "state": state,
                "type": agent_type,
                "args": args,
                "process_key": build_process_key(agent_type, tty, pid),
            }
        )

    return rows


def is_orphan_process(proc: dict) -> bool:
    tty = proc.get("tty", "")
    ppid = proc.get("ppid", 0)

    if tty == "??":
        return True

    if ppid in {0, 1}:
        return True

    return False


def find_active_agent_processes() -> List[dict]:
    seen_keys = set()
    active = []

    for proc in scan_target_processes():
        tty = proc.get("tty", "")
        process_key = proc.get("process_key", "")
        if tty == "??":
            continue
        if process_key in seen_keys:
            continue
        seen_keys.add(process_key)

        proc = dict(proc)
        proc["orphan"] = False
        active.append(proc)

    active.sort(key=lambda item: (item.get("type", ""), item.get("tty", ""), item.get("pid", 0)))
    return active


def find_orphan_agent_processes() -> List[dict]:
    orphans = []

    for proc in scan_target_processes():
        if is_orphan_process(proc):
            proc = dict(proc)
            proc["orphan"] = True
            orphans.append(proc)

    orphans.sort(key=lambda item: (item.get("type", ""), item.get("pid", 0)))
    return orphans


def terminate_process(pid: int, force: bool = False, timeout_sec: float = 2.0) -> Tuple[bool, str]:
    sig = signal.SIGKILL if force else signal.SIGTERM

    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return True, "process already exited"
    except PermissionError:
        return False, "permission denied"
    except Exception as exc:  # pragma: no cover
        return False, str(exc)

    if force:
        return True, "killed"

    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True, "terminated"
        except PermissionError:
            return False, "permission denied"
        time.sleep(0.1)

    return False, "still running"
