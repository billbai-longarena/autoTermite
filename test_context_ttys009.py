#!/usr/bin/env python3
"""
test_context_ttys009.py — 测试从 ttys009 (Claude) 读取上下文
"""

import subprocess

def get_terminal_content(tty_short):
    script = f'''
    tell application "Terminal"
        repeat with w in windows
            repeat with t in tabs of w
                if tty of t is "/dev/{tty_short}" then
                    try
                        return (history of t) as string
                    on error
                        return (contents of t) as string
                    end try
                end if
            end repeat
        end repeat
    end tell
    return "NOT_FOUND"
    '''
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=5)
        return r.stdout.strip()
    except Exception as e:
        return f"Error: {e}"

if __name__ == "__main__":
    tty = "ttys009"
    print(f"Testing direct read from {tty}...")
    res = get_terminal_content(tty)
    print(f"Length: {len(res)}")
    print("--- START ---")
    print(res[-500:] if len(res) > 0 else "EMPTY")
    print("--- END ---")
