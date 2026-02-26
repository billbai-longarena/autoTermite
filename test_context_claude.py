#!/usr/bin/env python3
"""
test_context_claude.py — 测试 claude 上下文读取功能
"""

import subprocess
import os

def try_method_2(tty_short):
    """
    Method 2: Iterate windows and get text (history)
    """
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

def find_claude_tty():
    try:
        # Use ps -e to see all processes
        r = subprocess.run(["ps", "-eo", "tty,args"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            # Match claude process
            if "claude" in line.lower() and "daemon" not in line.lower() and "grep" not in line:
                parts = line.split(None, 1)
                if len(parts) >= 1:
                    tty = parts[0]
                    if tty != "??":
                        return tty.replace("/dev/", "")
    except Exception as e:
        print(f"PS Error: {e}")
    return None

if __name__ == "__main__":
    tty = find_claude_tty()
    if tty:
        print(f"Target TTY: {tty}")
        
        print("\n--- Reading Claude Context ---")
        res = try_method_2(tty)
        print(f"Length: {len(res)}")
        if len(res) > 500:
            print("... (truncated)")
            print(res[-500:])
        else:
            print(res if len(res) > 0 else "EMPTY")
        
    else:
        print("No Claude process found.")
