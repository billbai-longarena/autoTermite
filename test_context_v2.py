#!/usr/bin/env python3
"""
test_context_v2.py — 尝试多种方式读取 codex 上下文
"""

import subprocess
import os

def try_method_1(tty_short):
    """
    Method 1: Direct 'contents of t'
    """
    script = f'''
    tell application "Terminal"
        repeat with w in windows
            repeat with t in tabs of w
                if tty of t is "/dev/{tty_short}" then
                    return (contents of t) as string
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

def try_method_2(tty_short):
    """
    Method 2: Iterate windows and get text (less specific)
    """
    script = f'''
    tell application "Terminal"
        repeat with w in windows
            repeat with t in tabs of w
                if tty of t is "/dev/{tty_short}" then
                    return (history of t) as string
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

def find_codex_tty():
    try:
        # Use ps -e to see all processes
        r = subprocess.run(["ps", "-eo", "tty,args"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            # Match strict codex process (avoid grep and daemon)
            if "codex" in line.lower() and "daemon" not in line.lower() and "grep" not in line:
                parts = line.split(None, 1)
                if len(parts) >= 1:
                    tty = parts[0]
                    if tty != "??":
                        return tty.replace("/dev/", "")
    except Exception as e:
        print(f"PS Error: {e}")
    return None

if __name__ == "__main__":
    tty = find_codex_tty()
    if tty:
        print(f"Target TTY: {tty}")
        
        print("\n--- Method 1 (contents) ---")
        res1 = try_method_1(tty)
        print(f"Length: {len(res1)}")
        print(res1[-200:] if len(res1) > 0 else "EMPTY")
        
        print("\n--- Method 2 (history) ---")
        res2 = try_method_2(tty)
        print(f"Length: {len(res2)}")
        print(res2[-200:] if len(res2) > 0 else "EMPTY")
        
    else:
        print("No Codex process found.")
