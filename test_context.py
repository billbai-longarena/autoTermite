#!/usr/bin/env python3
"""
test_context.py — 测试 codex 上下文读取功能
"""

import subprocess
import os

def get_terminal_content(tty):
    # 去掉 /dev/ 前缀以匹配 Applescript
    tty_short = tty.replace("/dev/", "")
    
    script = '''
    tell application "Terminal"
        repeat with w in windows
            repeat with t in tabs of w
                if tty of t is "/dev/{tty}" then
                    return (contents of t) as string
                end if
            end repeat
        end repeat
    end tell
    return ""
    '''.format(tty=tty_short)
    
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=5)
        return r.stdout
    except Exception as e:
        print(f"读取失败: {e}")
        return None

def find_codex_tty():
    try:
        r = subprocess.run(["ps", "-eo", "tty,args"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if "codex" in line and "daemon" not in line and "grep" not in line:
                parts = line.split(None, 1)
                if len(parts) >= 1:
                    tty = parts[0]
                    if tty != "??":
                        return tty
    except Exception as e:
        print(f"PS Error: {e}")
    return None

if __name__ == "__main__":
    tty = find_codex_tty()
    if tty:
        print(f"Found Codex at TTY: {tty}")
        content = get_terminal_content(tty)
        print("=== CONTEXT START ===")
        print(content[-500:] if content else "NO CONTENT")
        print("=== CONTEXT END ===")
    else:
        print("No Codex process found.")
