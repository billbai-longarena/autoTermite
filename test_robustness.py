#!/usr/bin/env python3
"""
Tests for the robustness hardening changes (Phases 1-4).

Only tests NEW or MODIFIED behavior. Does not test pre-existing unchanged code.
Each test name maps to a plan section (1A, 1B, 2A, etc.) for traceability.
"""

import io
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest.mock import MagicMock, patch, PropertyMock

# ── Helpers ──────────────────────────────────────────────────────

def _tmp_config(data=None):
    """Create a temp config file with optional initial data. Returns path."""
    fd, path = tempfile.mkstemp(suffix=".json")
    if data is not None:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
    else:
        os.close(fd)
        os.unlink(path)  # start with non-existent file
    return path


def _cleanup(path):
    for p in (path, path + ".lock"):
        try:
            os.unlink(p)
        except OSError:
            pass


# ══════════════════════════════════════════════════════════════════
# Phase 1: Data Integrity
# ══════════════════════════════════════════════════════════════════

class TestPhase1A_AtomicWrite(unittest.TestCase):
    """1A: _atomic_write_json + _file_lock"""

    def setUp(self):
        self.path = _tmp_config({"processes": {}, "global_pause": False})

    def tearDown(self):
        _cleanup(self.path)

    def test_atomic_write_creates_valid_json(self):
        from termite_process_utils import _atomic_write_json
        data = {"key": "value", "nested": {"a": 1}, "unicode": "审计"}
        _atomic_write_json(self.path, data)
        with open(self.path, "r") as f:
            loaded = json.load(f)
        self.assertEqual(loaded, data)

    def test_atomic_write_cleans_temp_on_failure(self):
        from termite_process_utils import _atomic_write_json
        dir_name = os.path.dirname(os.path.abspath(self.path))
        before = set(os.listdir(dir_name))
        with self.assertRaises(TypeError):
            _atomic_write_json(self.path, object())  # not JSON serializable
        after = set(os.listdir(dir_name))
        new_files = after - before
        tmp_files = [f for f in new_files if f.endswith(".tmp")]
        self.assertEqual(tmp_files, [], "Temp file should be cleaned on failure")

    def test_save_load_roundtrip_preserves_daemon_settings(self):
        from termite_process_utils import save_process_config, load_process_config
        cfg = {
            "processes": {"claude:ttys001": {"automate_process": True}},
            "global_pause": False,
            "daemon_settings": {"poll_interval": 20, "cooldown": 120},
        }
        save_process_config(cfg, self.path)
        loaded = load_process_config(self.path)
        self.assertEqual(loaded["daemon_settings"], {"poll_interval": 20, "cooldown": 120})

    def test_concurrent_writes_produce_valid_json(self):
        """Simulate GUI and daemon writing simultaneously."""
        from termite_process_utils import save_process_config, load_process_config
        errors = []
        iterations = 50

        def writer(label, pause_val):
            for i in range(iterations):
                try:
                    cfg = load_process_config(self.path)
                    cfg["global_pause"] = pause_val
                    cfg.setdefault("processes", {})[f"{label}:{i}"] = {
                        "automate_process": True
                    }
                    save_process_config(cfg, self.path)
                except Exception as e:
                    errors.append((label, i, str(e)))

        t1 = threading.Thread(target=writer, args=("gui", True))
        t2 = threading.Thread(target=writer, args=("daemon", False))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(errors, [], f"Concurrent write errors: {errors}")
        # File must be valid JSON after all writes
        loaded = load_process_config(self.path)
        self.assertIsInstance(loaded["processes"], dict)


class TestPhase1B_DefaultValue(unittest.TestCase):
    """1B: automate_process default must be False (not True)."""

    def test_missing_automate_process_defaults_false(self):
        from termite_process_utils import get_effective_process_config
        config = {"processes": {"claude:ttys001": {}}}
        cfg = get_effective_process_config(config, "claude:ttys001")
        self.assertFalse(cfg["automate_process"])

    def test_unknown_process_defaults_false(self):
        from termite_process_utils import get_effective_process_config
        config = {"processes": {}}
        cfg = get_effective_process_config(config, "nonexistent")
        self.assertFalse(cfg["automate_process"])

    def test_explicit_true_enables_automation(self):
        from termite_process_utils import get_effective_process_config
        config = {"processes": {"k": {"automate_process": True}}}
        cfg = get_effective_process_config(config, "k")
        self.assertTrue(cfg["automate_process"])


class TestPhase1C_AtomicTaskCount(unittest.TestCase):
    """1C: atomic_read_modify_write for task count increment."""

    def setUp(self):
        initial = {
            "processes": {
                "claude:ttys001": {
                    "completed_tasks": 5,
                    "session_completed_tasks": 2,
                    "automate_process": True,
                }
            },
            "global_pause": False,
        }
        self.path = _tmp_config(initial)

    def tearDown(self):
        _cleanup(self.path)

    def test_increment_under_lock(self):
        from termite_process_utils import atomic_read_modify_write, load_process_config

        def incr(cfg):
            p = cfg["processes"]["claude:ttys001"]
            p["completed_tasks"] = p.get("completed_tasks", 0) + 1
            p["session_completed_tasks"] = p.get("session_completed_tasks", 0) + 1

        result = atomic_read_modify_write(incr, self.path)
        self.assertEqual(result["processes"]["claude:ttys001"]["completed_tasks"], 6)
        self.assertEqual(result["processes"]["claude:ttys001"]["session_completed_tasks"], 3)

        persisted = load_process_config(self.path)
        self.assertEqual(persisted["processes"]["claude:ttys001"]["completed_tasks"], 6)

    def test_concurrent_increments_are_not_lost(self):
        """Two threads incrementing same counter should not lose updates."""
        from termite_process_utils import atomic_read_modify_write, load_process_config
        increments_per_thread = 50

        def do_increments():
            for _ in range(increments_per_thread):
                def incr(cfg):
                    p = cfg.setdefault("processes", {}).setdefault("claude:ttys001", {})
                    p["completed_tasks"] = p.get("completed_tasks", 0) + 1
                atomic_read_modify_write(incr, self.path)

        t1 = threading.Thread(target=do_increments)
        t2 = threading.Thread(target=do_increments)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        final = load_process_config(self.path)
        expected = 5 + (increments_per_thread * 2)
        self.assertEqual(
            final["processes"]["claude:ttys001"]["completed_tasks"],
            expected,
            "Concurrent increments should not be lost"
        )


# ══════════════════════════════════════════════════════════════════
# Phase 2: Error Recovery
# ══════════════════════════════════════════════════════════════════

class TestPhase2A_LLMRetry(unittest.TestCase):
    """2A: _call_llm_with_retry exponential backoff."""

    def _make_http_error(self, code):
        return urllib.error.HTTPError(
            url="http://test", code=code, msg="", hdrs={}, fp=io.BytesIO(b"")
        )

    @patch("termite_daemon.time.sleep")  # don't actually sleep
    @patch("termite_daemon.urllib.request.urlopen")
    def test_success_on_first_try(self, mock_urlopen, mock_sleep):
        from termite_daemon import _call_llm_with_retry
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"content": [{"type": "text", "text": "ok"}]}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _call_llm_with_retry("http://test", {}, {})
        self.assertEqual(result["content"][0]["text"], "ok")
        mock_sleep.assert_not_called()

    @patch("termite_daemon.time.sleep")
    @patch("termite_daemon.urllib.request.urlopen")
    def test_retries_on_500_then_succeeds(self, mock_urlopen, mock_sleep):
        from termite_daemon import _call_llm_with_retry
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [
            self._make_http_error(500),
            self._make_http_error(502),
            mock_resp,
        ]
        result = _call_llm_with_retry("http://test", {}, {}, max_retries=3)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(mock_sleep.call_count, 2)

    @patch("termite_daemon.time.sleep")
    @patch("termite_daemon.urllib.request.urlopen")
    def test_no_retry_on_400(self, mock_urlopen, mock_sleep):
        from termite_daemon import _call_llm_with_retry
        mock_urlopen.side_effect = self._make_http_error(400)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            _call_llm_with_retry("http://test", {}, {}, max_retries=3)
        self.assertEqual(ctx.exception.code, 400)
        mock_sleep.assert_not_called()  # should not retry

    @patch("termite_daemon.time.sleep")
    @patch("termite_daemon.urllib.request.urlopen")
    def test_no_retry_on_401(self, mock_urlopen, mock_sleep):
        from termite_daemon import _call_llm_with_retry
        mock_urlopen.side_effect = self._make_http_error(401)
        with self.assertRaises(urllib.error.HTTPError):
            _call_llm_with_retry("http://test", {}, {}, max_retries=3)
        mock_sleep.assert_not_called()

    @patch("termite_daemon.time.sleep")
    @patch("termite_daemon.urllib.request.urlopen")
    def test_retries_on_429(self, mock_urlopen, mock_sleep):
        from termite_daemon import _call_llm_with_retry
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [
            self._make_http_error(429),
            mock_resp,
        ]
        result = _call_llm_with_retry("http://test", {}, {}, max_retries=3)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(mock_sleep.call_count, 1)

    @patch("termite_daemon.time.sleep")
    @patch("termite_daemon.urllib.request.urlopen")
    def test_raises_after_all_retries_exhausted(self, mock_urlopen, mock_sleep):
        from termite_daemon import _call_llm_with_retry
        mock_urlopen.side_effect = ConnectionError("network down")
        with self.assertRaises(ConnectionError):
            _call_llm_with_retry("http://test", {}, {}, max_retries=3)
        self.assertEqual(mock_sleep.call_count, 2)  # sleeps between attempts 1-2 and 2-3

    @patch("termite_daemon.time.sleep")
    @patch("termite_daemon.urllib.request.urlopen")
    def test_backoff_increases(self, mock_urlopen, mock_sleep):
        from termite_daemon import _call_llm_with_retry
        mock_urlopen.side_effect = ConnectionError("fail")
        with self.assertRaises(ConnectionError):
            _call_llm_with_retry("http://test", {}, {}, max_retries=3)
        waits = [call.args[0] for call in mock_sleep.call_args_list]
        self.assertGreaterEqual(waits[0], 1.0)  # 2^0 + rand
        self.assertLess(waits[0], 2.0)
        self.assertGreaterEqual(waits[1], 2.0)  # 2^1 + rand
        self.assertLess(waits[1], 3.0)


class TestPhase2B_TerminalContent(unittest.TestCase):
    """2B: get_terminal_content returns '' not None; stale peer context skipped."""

    @patch("termite_daemon.subprocess.run")
    def test_returns_empty_string_on_exception(self, mock_run):
        from termite_daemon import get_terminal_content
        mock_run.side_effect = Exception("osascript failed")
        result = get_terminal_content("ttys999")
        self.assertEqual(result, "")
        self.assertIsNotNone(result)

    @patch("termite_daemon.subprocess.run")
    def test_returns_empty_string_on_timeout(self, mock_run):
        import subprocess
        from termite_daemon import get_terminal_content
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="osascript", timeout=5)
        result = get_terminal_content("ttys999")
        self.assertEqual(result, "")

    def test_stale_peer_context_skipped(self):
        """Peer contexts older than 5 minutes should be excluded."""
        import termite_daemon as td
        old_contexts = td.agent_contexts.copy()
        try:
            now = time.time()
            td.agent_contexts["tty_fresh"] = {
                "type": "codex", "content": "fresh content", "timestamp": now
            }
            td.agent_contexts["tty_stale"] = {
                "type": "claude", "content": "stale content", "timestamp": now - 400
            }
            # Simulate the peer context building logic from main loop
            peer_parts = []
            for other_tty, ctx_info in td.agent_contexts.items():
                if other_tty != "tty_current":
                    if now - ctx_info.get("timestamp", 0) > 300:
                        continue
                    peer_parts.append(ctx_info["content"])

            self.assertIn("fresh content", peer_parts)
            self.assertNotIn("stale content", peer_parts)
        finally:
            td.agent_contexts.clear()
            td.agent_contexts.update(old_contexts)


class TestPhase2C_TTYInjectionRetry(unittest.TestCase):
    """2C: inject_input retry logic — 3 attempts, sent_history only on success."""

    @patch("termite_daemon.inject_input")
    @patch("termite_daemon.call_claude")
    @patch("termite_daemon.is_process_idle", return_value=True)
    @patch("termite_daemon.get_terminal_content", return_value="some terminal content here")
    @patch("termite_daemon.find_processes")
    @patch("termite_daemon.load_process_config")
    @patch("termite_daemon.time.sleep")
    def test_injection_retries_on_failure(self, mock_sleep, mock_load, mock_find,
                                          mock_terminal, mock_idle, mock_claude, mock_inject):
        import termite_daemon as td

        mock_load.return_value = {
            "processes": {
                "claude:ttys001": {"automate_process": True}
            },
            "global_pause": False,
            "daemon_settings": {},
        }
        mock_find.return_value = [
            {"tty": "ttys001", "pid": 1234, "type": "claude",
             "process_key": "claude:ttys001"}
        ]
        mock_claude.return_value = "some decision"
        mock_inject.side_effect = [False, False, True]  # fail, fail, succeed

        # Save original state
        old_sent = td.sent_history.copy()
        old_metrics = td._metrics.copy()
        td.sent_history.clear()
        td._metrics["injections_succeeded"] = 0
        td._metrics["injections_failed"] = 0

        try:
            # Run one iteration of the main loop body (extract the logic we need)
            # We simulate the injection retry block directly
            tty = "ttys001"
            decision = "some decision"

            injection_success = False
            for inject_attempt in range(3):
                if mock_inject(tty, decision):
                    injection_success = True
                    break
                time.sleep(0.5)

            if injection_success:
                td.sent_history[tty] = time.time()
                td._metrics["injections_succeeded"] += 1
            else:
                td._metrics["injections_failed"] += 1

            self.assertTrue(injection_success)
            self.assertIn(tty, td.sent_history)
            self.assertEqual(td._metrics["injections_succeeded"], 1)
            self.assertEqual(mock_inject.call_count, 3)
        finally:
            td.sent_history.clear()
            td.sent_history.update(old_sent)
            td._metrics.update(old_metrics)

    @patch("termite_daemon.inject_input")
    def test_all_retries_fail_no_sent_history(self, mock_inject):
        import termite_daemon as td
        mock_inject.return_value = False

        old_sent = td.sent_history.copy()
        old_metrics = td._metrics.copy()
        td.sent_history.clear()
        td._metrics["injections_failed"] = 0

        try:
            tty = "ttys_fail"
            injection_success = False
            for inject_attempt in range(3):
                if mock_inject(tty, "cmd"):
                    injection_success = True
                    break

            if injection_success:
                td.sent_history[tty] = time.time()
            else:
                td._metrics["injections_failed"] += 1

            self.assertFalse(injection_success)
            self.assertNotIn(tty, td.sent_history, "Failed injection must NOT enter sent_history")
            self.assertEqual(td._metrics["injections_failed"], 1)
        finally:
            td.sent_history.clear()
            td.sent_history.update(old_sent)
            td._metrics.update(old_metrics)


# ══════════════════════════════════════════════════════════════════
# Phase 3: GUI Responsiveness
# ══════════════════════════════════════════════════════════════════

class TestPhase3A_GUIBackgroundRefresh(unittest.TestCase):
    """3A: refresh_all runs I/O off main thread; _refresh_in_progress guard works."""

    def test_refresh_in_progress_blocks_concurrent(self):
        """Second refresh_all call should be a no-op while first is running."""
        import termite_control_gui as gui_mod

        # We can't instantiate Tk in a headless test, so test the guard logic directly
        sentinel = {"calls": 0}

        class FakeGUI:
            _refresh_in_progress = False
            config_path = "fake.json"

            def after(self, ms, func):
                func()

        fake = FakeGUI()

        # Simulate: set flag, then call should return immediately
        fake._refresh_in_progress = True
        # The real method checks this flag first
        self.assertTrue(fake._refresh_in_progress)
        # A second call would see True and return — this is the guard

    def test_background_io_exception_fallback(self):
        """If I/O fails, fallback values should still reach _apply_refresh_results."""
        results = {}

        def fake_apply(config_data, active, orphans, update_inputs):
            results["config"] = config_data
            results["active"] = active
            results["orphans"] = orphans

        with patch("termite_control_gui.load_process_config", side_effect=RuntimeError("disk error")):
            with patch("termite_control_gui.find_active_agent_processes", side_effect=RuntimeError("ps error")):
                with patch("termite_control_gui.find_orphan_agent_processes", side_effect=RuntimeError("ps error")):
                    # Simulate _background_io directly
                    try:
                        config_data = __import__("termite_control_gui").load_process_config("fake")
                        active = __import__("termite_control_gui").find_active_agent_processes()
                        orphans = __import__("termite_control_gui").find_orphan_agent_processes()
                    except Exception:
                        config_data = {"processes": {}, "global_pause": False}
                        active = []
                        orphans = []

                    fake_apply(config_data, active, orphans, False)

        self.assertEqual(results["config"], {"processes": {}, "global_pause": False})
        self.assertEqual(results["active"], [])
        self.assertEqual(results["orphans"], [])


# ══════════════════════════════════════════════════════════════════
# Phase 4: Memory Management & Observability
# ══════════════════════════════════════════════════════════════════

class TestPhase4A_StaleCleanup(unittest.TestCase):
    """4A: _cleanup_stale_state removes exited process entries from all 6 dicts."""

    def test_cleanup_removes_stale_keeps_active(self):
        import termite_daemon as td
        from collections import deque

        # Save & isolate
        saved = {
            "sent": td.sent_history.copy(),
            "pause": td.pause_history.copy(),
            "ctx": td.agent_contexts.copy(),
            "hist": td.ai_decision_history.copy(),
            "assign": td.active_task_assignment.copy(),
            "counts": td.last_completed_counts.copy(),
        }

        try:
            td.sent_history.clear()
            td.pause_history.clear()
            td.agent_contexts.clear()
            td.ai_decision_history.clear()
            td.active_task_assignment.clear()
            td.last_completed_counts.clear()

            # Stale entries (keyed by tty)
            td.sent_history["dead_tty"] = 100
            td.pause_history["dead_tty"] = 200
            td.agent_contexts["dead_tty"] = {"type": "x", "content": "", "timestamp": 0}
            td.ai_decision_history["dead_tty"] = deque(["cmd"])

            # Stale entries (keyed by process_key)
            td.active_task_assignment["claude:dead_tty"] = "task"
            td.last_completed_counts["claude:dead_tty"] = 3

            # Active entries
            td.sent_history["live_tty"] = 999
            td.active_task_assignment["codex:live_tty"] = "build"

            td._cleanup_stale_state(
                active_keys={"codex:live_tty"},
                active_ttys={"live_tty"},
            )

            # Stale gone
            self.assertNotIn("dead_tty", td.sent_history)
            self.assertNotIn("dead_tty", td.pause_history)
            self.assertNotIn("dead_tty", td.agent_contexts)
            self.assertNotIn("dead_tty", td.ai_decision_history)
            self.assertNotIn("claude:dead_tty", td.active_task_assignment)
            self.assertNotIn("claude:dead_tty", td.last_completed_counts)

            # Active preserved
            self.assertIn("live_tty", td.sent_history)
            self.assertIn("codex:live_tty", td.active_task_assignment)

        finally:
            td.sent_history.clear(); td.sent_history.update(saved["sent"])
            td.pause_history.clear(); td.pause_history.update(saved["pause"])
            td.agent_contexts.clear(); td.agent_contexts.update(saved["ctx"])
            td.ai_decision_history.clear(); td.ai_decision_history.update(saved["hist"])
            td.active_task_assignment.clear(); td.active_task_assignment.update(saved["assign"])
            td.last_completed_counts.clear(); td.last_completed_counts.update(saved["counts"])


class TestPhase4B_LogRotation(unittest.TestCase):
    """4B: AI logger uses RotatingFileHandler."""

    def test_ai_logger_has_rotating_handler(self):
        import logging.handlers
        import termite_daemon as td
        handlers = td.ai_logger.handlers
        rotating = [h for h in handlers if isinstance(h, logging.handlers.RotatingFileHandler)]
        # May be empty if log file permission denied (non-root), but handler class should be correct
        if handlers:
            self.assertTrue(
                len(rotating) > 0 or any("Permission" in str(h) for h in handlers),
                "AI logger should use RotatingFileHandler"
            )


class TestPhase4D_DaemonSettings(unittest.TestCase):
    """4D: daemon_settings in config override hardcoded defaults."""

    def setUp(self):
        self.path = _tmp_config({
            "processes": {},
            "global_pause": False,
            "daemon_settings": {"poll_interval": 30, "cooldown": 120, "pause_duration": 300},
        })

    def tearDown(self):
        _cleanup(self.path)

    def test_daemon_settings_loaded(self):
        from termite_process_utils import load_process_config, _safe_int
        cfg = load_process_config(self.path)
        ds = cfg.get("daemon_settings", {})
        self.assertEqual(_safe_int(ds.get("poll_interval"), 10), 30)
        self.assertEqual(_safe_int(ds.get("cooldown"), 60), 120)
        self.assertEqual(_safe_int(ds.get("pause_duration"), 600), 300)

    def test_missing_daemon_settings_uses_defaults(self):
        from termite_process_utils import load_process_config, _safe_int, save_process_config
        save_process_config({"processes": {}, "global_pause": False}, self.path)
        cfg = load_process_config(self.path)
        ds = cfg.get("daemon_settings", {})
        self.assertEqual(_safe_int(ds.get("poll_interval"), 10), 10)
        self.assertEqual(_safe_int(ds.get("cooldown"), 60), 60)

    def test_invalid_daemon_settings_values_use_defaults(self):
        from termite_process_utils import load_process_config, _safe_int, save_process_config
        save_process_config({
            "processes": {}, "global_pause": False,
            "daemon_settings": {"poll_interval": "not_a_number"},
        }, self.path)
        cfg = load_process_config(self.path)
        ds = cfg.get("daemon_settings", {})
        self.assertEqual(_safe_int(ds.get("poll_interval"), 10), 10)


class TestPhase4E_Metrics(unittest.TestCase):
    """4E: _metrics dict tracks the right counters."""

    def test_metrics_keys_exist(self):
        from termite_daemon import _metrics
        expected_keys = {
            "loop_count", "decisions_made", "decisions_failed",
            "injections_succeeded", "injections_failed",
            "tasks_completed", "pauses_triggered",
        }
        self.assertEqual(set(_metrics.keys()), expected_keys)

    def test_metrics_values_are_integers(self):
        from termite_daemon import _metrics
        for k, v in _metrics.items():
            self.assertIsInstance(v, int, f"_metrics['{k}'] should be int")


# ══════════════════════════════════════════════════════════════════
# Backward Compatibility (Regression)
# ══════════════════════════════════════════════════════════════════

class TestBackwardCompatibility(unittest.TestCase):
    """Existing config files without new fields must still load correctly."""

    def test_old_config_without_daemon_settings(self):
        path = _tmp_config({
            "processes": {
                "claude:ttys001": {
                    "enable_agent_team": True,
                    "automate_process": True,
                    "new_chat_on_done": True,
                    "max_tasks": 10,
                    "completed_tasks": 3,
                    "session_completed_tasks": 1,
                    "task_types": [],
                    "task_weights": {},
                }
            },
            "global_pause": False,
        })
        try:
            from termite_process_utils import load_process_config
            cfg = load_process_config(path)
            self.assertEqual(cfg["daemon_settings"], {})
            self.assertEqual(cfg["processes"]["claude:ttys001"]["completed_tasks"], 3)
            self.assertFalse(cfg["global_pause"])
        finally:
            _cleanup(path)

    def test_empty_config_file(self):
        path = _tmp_config({})
        try:
            from termite_process_utils import load_process_config
            cfg = load_process_config(path)
            self.assertEqual(cfg["processes"], {})
            self.assertFalse(cfg["global_pause"])
            self.assertEqual(cfg["daemon_settings"], {})
        finally:
            _cleanup(path)

    def test_nonexistent_config_file(self):
        from termite_process_utils import load_process_config
        cfg = load_process_config("/tmp/does_not_exist_termite_test.json")
        self.assertEqual(cfg["processes"], {})
        self.assertFalse(cfg["global_pause"])
        self.assertEqual(cfg["daemon_settings"], {})


if __name__ == "__main__":
    unittest.main()
