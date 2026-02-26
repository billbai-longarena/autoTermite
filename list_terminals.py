#!/usr/bin/env python3
"""
list_terminals.py — 列出所有 Terminal.app 窗口的 TTY
"""

import subprocess

def list_terminals():
    script = '''
    tell application "Terminal"
        set output to ""
        repeat with w in windows
            set w_id to id of w
            repeat with t in tabs of w
                set tty_name to tty of t
                set output to output & "Window: " & w_id & " | TTY: " & tty_name & "\n"
            end repeat
        end repeat
        return output
    end tell
    '''
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=5)
        print(r.stdout)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    list_terminals()
