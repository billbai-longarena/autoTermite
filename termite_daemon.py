#!/usr/bin/env python3
"""
termite_daemon.py — 智能白蚁守护程序
Intelligent Termite Daemon powered by Claude Sonnet 4.6

驱动:
  1. codex (Construction)
  2. claude (Audit/Design/Review)

逻辑:
  1. 监控进程 (codex, claude)
  2. 判定空闲 (CPU time monitoring)
  3. 读取终端上下文
  4. 调用 LLM (Claude Sonnet 4.6) 决策
  5. 注入输入
  6. 持久化 AI 对话日志 (termite_ai.log)
  7. 工作负载平衡 (Workload Pacing): 控制 Claude 仅领先 Codex 5-6 个任务，超时休息
"""

import fcntl
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
from termite_process_utils import (
    CONFIG_FILE,
    find_active_agent_processes,
    get_effective_process_config,
    load_process_config,
)

# ── 配置 ──────────────────────────────────────────────────────────
POLL_INTERVAL = 10         # 主循环扫描间隔 (秒)
COOLDOWN = 60              # 同一 TTY 冷却时间 (秒)，加长以避免频繁打断
IDLE_SAMPLES = 3           # 空闲检测采样次数
IDLE_INTERVAL = 5          # 空闲检测采样间隔 (秒)
CPU_DELTA_THRESHOLD = 0.05 # 每个间隔允许的最大 CPU 时间增量 (秒)
PAUSE_DURATION = 600       # Claude 休息时间 (秒)
LOG_FILE = "termite_ai.log"

# macOS TIOCSTI ioctl
TIOCSTI = 0x80017472

# ── 日志 ──────────────────────────────────────────────────────────
# 控制台日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
log = logging.getLogger("termite-daemon")

# AI 交互日志 (独立文件)
ai_logger = logging.getLogger("termite-ai")
ai_logger.setLevel(logging.INFO)
ai_logger.propagate = False
try:
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    ai_logger.addHandler(file_handler)
except Exception as e:
    log.error("无法创建 AI 日志文件: %s", e)

from collections import deque

# ── 状态 ──────────────────────────────────────────────────────────
sent_history = {}
pause_history = {} # 记录暂停结束时间: {tty: timestamp}
agent_contexts = {} # 缓存各 agent 的上下文: {tty: content}
env_config = {}
protocol_content = ""
# 记录每个 agent(tty) 最近给出的最多 10 条指令，帮助 AI 理解进度
ai_decision_history = {} # {tty: deque(maxlen=10)}

# ── 初始化 ────────────────────────────────────────────────────────

def load_env():
    """加载 .env 配置"""
    global env_config
    try:
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    env_config[k.strip()] = v.strip()
        log.info("已加载 .env 配置")
    except Exception as e:
        log.error("无法加载 .env: %s", e)
        sys.exit(1)

def load_protocol():
    """加载 Termite Protocol"""
    global protocol_content
    try:
        with open("TERMITE_PROTOCOL.md", "r", encoding="utf-8") as f:
            protocol_content = f.read()
        log.info("已加载 TERMITE_PROTOCOL.md (%d chars)", len(protocol_content))
    except Exception as e:
        log.error("无法加载协议文件: %s", e)
        protocol_content = "Termite Protocol not found. Proceed with best judgment for software engineering tasks."

def log_ai_interaction(agent, context, decision):
    """记录 AI 交互详情到日志文件"""
    msg = f"[{agent}] IDLE DETECTED\n"
    msg += f"=== CONTEXT (Last 2000 chars) ===\n{context[-2000:]}\n"
    msg += f"=== AI DECISION ===\n{decision}\n"
    msg += "="*60
    ai_logger.info(msg)

def clean_ansi_escape_sequences(text):
    """清除终端输出中的 ANSI 转义序列，减少 Token 消耗，提高 LLM 理解率"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

# ── LLM 调用 ──────────────────────────────────────────────────────

def call_claude(agent_name, screen_content, peer_context=None, override_prompt=None, tty=None):
    """调用 Claude Sonnet 4.6 决策下一步输入"""
    endpoint = "https://bill-3691-resource.services.ai.azure.com/anthropic/v1/messages"
    api_key = env_config.get("AZURE_ANTHROPIC_API_KEY", "")
    
    peer_info = ""
    if peer_context:
        peer_info = (
            "\n\n=== 其他合作伙伴状态 ===\n"
            f"{peer_context}\n"
            "============================\n"
            "请参考以上其他智能体的状态，来决定是否需要配合、等待或暂停节奏。\n"
        )

    # 附加上近期发送给该 agent 的最多 10 条指令
    recent_instructions = list(ai_decision_history.get(tty, [])) if tty else []
    history_info = ""
    if recent_instructions:
        history_info = "\n\n=== 最近给该 Agent 发送的 10 条指令历史 ===\n"
        for idx, inst in enumerate(recent_instructions, 1):
            history_info += f"{idx}. {inst}\n"
        history_info += "=========================================\n"
        history_info += "请参考以上近期指令来判断：1) 是否陷入了重复循环；2) 当前处于任务的哪个阶段；3) 什么时候该让其结束或重启。\n"
        history_info += "注意：如果发现最近的几条指令是重复的且任务发生阻塞（没有任何进展），你需要保持随机应变，尝试发出不同角度或更明确的指导指令以打破僵局，而不是死板地重复同一句话。\n"

    system_prompt = (
        "You are the Termite Daemon, an intelligent overseer (哨兵) for AI agents in a software engineering swarm. "
        f"You are currently driving the agent: '{agent_name}'.\n"
        f"{peer_info}"
        "Your CORE RESPONSIBILITY is to monitor the agent's terminal state and provide the minimal necessary input to keep it productive or force it to converge. "
        "The agents themselves already know the TERMITE_PROTOCOL, so you DO NOT need to micromanage their tasks. You are just pressing the right buttons at the right time.\n\n"
        "=== AGENT-SPECIFIC STRATEGIES ===\n\n"
        "1. **codex** (The Builder):\n"
        "   - Codex tends to explore endlessly and might polish code forever. **Your primary job for Codex is to detect completion and force convergence.**\n"
        "   - **State A (Force Convergence)**: If the terminal shows Codex has made significant progress (e.g. committed code, `[WIP]` commits, updated BLACKBOARD, tests passed) OR if it looks like it is 'polishing' without necessity, you MUST interrupt it by outputting EXACTLY:\n"
        "     `根据白蚁协议，确认是否完成？`\n"
        "   - **State B (Reset & Next)**: If Codex explicitly answers that it has completed the task (e.g. '已完成', '结论：已完成') AND it is currently waiting for your instruction to start a new task, you MUST clear its context to prevent loops by outputting EXACTLY:\n"
        "     `/new`\n"
        "     *CRITICAL AVOID LOOP*: If you see that `/new` was already executed recently (e.g. visible at the end of the terminal or in the recent instructions history) and Codex is waiting at a fresh prompt, DO NOT output `/new` again. Proceed to State C.\n"
        "   - **State C (Normal Progression)**: If Codex is just starting a task, sitting at a fresh prompt after `/new`, or clearly needs to take the next normal step, output EXACTLY:\n"
        "     `1 按照白蚁协议，进行最佳下一步（注意：如果开始新任务，请务必先确保当前工作已提交。有条件push就要及时push。且启用多Agent进行并行开发）`\n"
        "     *CRITICAL AVOID LOOP*: Do not output this repeatedly if the previous instruction was identical and no meaningful progress or new prompt is shown. Break the loop by asking a specific question instead.\n"
        "   - If it explicitly asks you for permission to run a test or command (e.g. '要我继续验证吗？'), you can reply `y` or directly instruct it to run the verification.\n"
        "   - **Special Case (Missing .env)**: If Codex complains about missing `.env` with test database information (usually because it's in a new worktree), instruct it to use the `.env` from the `backend/` directory.\n\n"
        "2. **claude code** (The Auditor/Architect):\n"
        "   - Claude does not need to be driven as frequently. It audits and designs.\n"
        "   - **STRICT ROLE ENFORCEMENT**: Claude is STRICTLY FORBIDDEN from writing implementation code, fixing bugs directly, or running complex coding tasks. If you see Claude attempting to fix bugs (e.g., 'fix S-xxx') or write feature code instead of reviewing/designing, you MUST STOP it immediately by outputting EXACTLY:\n"
        "     `根据白蚁协议，你作为 Auditor/Architect 严禁直接修改代码或修复 Bug，请将修复工作留给 Codex。现在请退回并选择一个你需要做的【审计】或【设计】任务。`\n"
        "   - **WORKLOAD PACING (CRITICAL)**: Maintain a lead of only 5-6 tasks over Codex. If Claude has > 6 unfinished designs/pending reviews, or if you feel it's moving too fast compared to Codex, output EXACTLY:\n"
        "     `[PAUSE]`\n"
        "   - **Normal Progression**: If Claude is idle and waiting for instructions (and not violating its role), drive it with:\n"
        "     `根据白蚁协议，选一个最重要的任务开始审计或设计（注意：在开始新任务前务必确保当前工作已提交。有条件push就要及时push。）`\n"
        "     OR\n"
        "     `根据白蚁协议，对已经完成的任务进行代码评审`\n\n"
        "=== INSTRUCTIONS ===\n"
        "Analyze the provided, cleaned terminal output.\n"
        "Determine the CURRENT STATE of the agent and provide the best next input string.\n"
        "OUTPUT ONLY the raw text string to send. NO markdown, NO explanations, NO quotes, NO code blocks.\n"
    )

    clean_content = clean_ansi_escape_sequences(screen_content)
    user_content = f"Here is the current terminal screen content for {agent_name}:\n\n{clean_content[-3000:]}\n\n*** IMPORTANT: The very last lines of the output represent the CURRENT state. If the last command was `/new`, do NOT output `/new` again. ***"
    if override_prompt:
        user_content += f"\n\n*** 紧急指令 ***\n{override_prompt}"

    payload = {
        "model": "claude-sonnet-4-6",
        "max_tokens": 500,
        "temperature": 0.3,
        "system": system_prompt,
        "messages": [
            {
                "role": "user", 
                "content": user_content
            }
        ]
    }

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01"
    }

    try:
        req = urllib.request.Request(endpoint, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req) as response:
            resp_data = json.loads(response.read().decode('utf-8'))
            content = resp_data.get("content", [])
            text = ""
            for block in content:
                if block.get("type") == "text":
                    text += block.get("text", "")
            decision = text.strip()
            # 记录日志
            log_ai_interaction(agent_name, screen_content, decision)
            return decision
    except Exception as e:
        log.error("LLM 调用失败: %s", e)
        return None

# ── 进程检测 ──────────────────────────────────────────────────────

def find_processes():
    """扫描进程表, 返回目标进程列表"""
    return find_active_agent_processes()

# ── CPU 时间空闲检测 ──────────────────────────────────────────────

def parse_cputime(s):
    s = s.strip()
    if not s: return -1.0
    parts = s.split(":")
    try:
        if len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
        elif len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
    except ValueError:
        pass
    return -1.0

def get_process_cputime(pid):
    pids = [str(pid)]
    try:
        r = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True, timeout=5)
        children = [p.strip() for p in r.stdout.split() if p.strip()]
        pids.extend(children)
        for cpid in children:
            r2 = subprocess.run(["pgrep", "-P", cpid], capture_output=True, text=True, timeout=5)
            pids.extend([p.strip() for p in r2.stdout.split() if p.strip()])
    except Exception:
        pass

    pid_arg = ",".join(pids)
    try:
        r = subprocess.run(["ps", "-p", pid_arg, "-o", "cputime="], capture_output=True, text=True, timeout=5)
        total = 0.0
        for line in r.stdout.splitlines():
            t = parse_cputime(line)
            if t >= 0: total += t
        return total
    except Exception:
        return -1.0

def is_process_idle(pid, label):
    prev = get_process_cputime(pid)
    if prev < 0: return False

    for i in range(IDLE_SAMPLES - 1):
        time.sleep(IDLE_INTERVAL)
        curr = get_process_cputime(pid)
        if curr < 0: return False
        delta = curr - prev
        if delta > CPU_DELTA_THRESHOLD:
            # 改为 debug 级别，减少刷屏
            log.debug("    [%s] 采样 %d: CPU 增量 %.3fs > 阈值, 忙碌中", label, i + 1, delta)
            return False
        prev = curr
    return True

# ── 读取终端 ──────────────────────────────────────────────────────

def get_terminal_content(tty):
    script = '''
    tell application "Terminal"
        repeat with w in windows
            repeat with t in tabs of w
                if tty of t is "/dev/{tty}" then
                    try
                        return (history of t) as string
                    on error
                        return (contents of t) as string
                    end try
                end if
            end repeat
        end repeat
    end tell
    return ""
    '''.format(tty=tty)
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=5)
        return r.stdout
    except Exception as e:
        log.error("读取终端失败: %s", e)
        return None

# ── 输入注入 ──────────────────────────────────────────────────────

def inject_input(tty, text):
    tty_path = "/dev/{}".format(tty)
    try:
        fd = os.open(tty_path, os.O_RDWR)
    except OSError as e:
        log.error("无法打开 %s: %s", tty_path, e)
        return False
    try:
        for b in text.encode("utf-8"):
            fcntl.ioctl(fd, TIOCSTI, bytes([b]))
        time.sleep(0.2)
        fcntl.ioctl(fd, TIOCSTI, b"\r")
        return True
    except OSError as e:
        log.error("TIOCSTI 失败: %s", e)
        return False
    finally:
        os.close(fd)

# ── 主循环 ────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        log.warning("请使用 sudo 运行以获得 TTY 控制权限")
    
    load_env()
    load_protocol()
    
    log.info("Termite Daemon (Intelligent) 启动")
    log.info("监控目标: codex, claude")
    log.info("模型: claude-sonnet-4-6")
    log.info("日志: %s", LOG_FILE)
    log.info("进程配置: %s", CONFIG_FILE)
    log.info("Pacing: Claude lead max 6 tasks, pause %ds", PAUSE_DURATION)
    
    def shutdown(sig, frame):
        log.info("正在退出...")
        sys.exit(0)
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        try:
            now = time.time()
            # 清理冷却
            to_del = [t for t, ts in sent_history.items() if now - ts > COOLDOWN]
            for t in to_del: del sent_history[t]
            
            runtime_config = load_process_config(CONFIG_FILE)
            
            if runtime_config.get("global_pause", False):
                time.sleep(POLL_INTERVAL)
                continue
                
            processes = find_processes()
            
            for proc in processes:
                tty = proc["tty"]
                pid = proc["pid"]
                atype = proc["type"]
                process_key = proc.get("process_key", f"{atype}:{tty}")
                process_cfg = get_effective_process_config(runtime_config, process_key)

                if not process_cfg.get("automate_process", True):
                    continue
                
                if tty in sent_history:
                    continue

                # 检查是否暂停
                is_waking_up = False
                if tty in pause_history:
                    remaining = int(pause_history[tty] - now)
                    if remaining > 0:
                        # 避免刷屏，不记录日志
                        continue
                    else:
                        # 暂停时间结束，进入唤醒检查流程
                        is_waking_up = True
                        log.info("  [WAKE UP] %s 暂停结束，进行状态检查...", atype)

                # 只有空闲且需要交互时才 logging (在 is_process_idle 内部已降级忙碌日志)
                if not is_process_idle(pid, atype):
                    continue
                
                log.info("  [%s] 判定为空闲, 读取上下文...", atype)
                content = get_terminal_content(tty)
                if not content or len(content.strip()) < 10:
                    log.warning("  [%s] 终端内容为空或无法读取", atype)
                    continue

                # 更新上下文缓存
                agent_contexts[tty] = {
                    "type": atype,
                    "content": content
                }

                # 提取其他伙伴的上下文，支持多个 agent
                peer_context = None
                if process_cfg.get("enable_agent_team", True):
                    peer_context_parts = []
                    for other_tty, ctx_info in agent_contexts.items():
                        if other_tty != tty:
                            peer_type = ctx_info["type"]
                            peer_content = ctx_info["content"]
                            peer_context_parts.append(f"--- 另一个 Agent ({peer_type} @ {other_tty}) 的状态 ---\n{peer_content[-1500:]}\n")
                    peer_context = "\n".join(peer_context_parts) if peer_context_parts else None

                # 准备 override prompt
                override_prompt_parts = []
                if is_waking_up and atype == "claude":
                    override_prompt_parts.append("根据白蚁协议，目前有多少个未完成的任务？如果 Codex 的工作积压仍然很高，请输出 [PAUSE] 以继续等待。")
                if not process_cfg.get("enable_agent_team", True):
                    override_prompt_parts.append("当前进程配置关闭了 agent team。不要依赖或等待其他 agent 的协作信息，请单独推进。")
                if not process_cfg.get("new_chat_on_done", True):
                    override_prompt_parts.append("当前进程配置禁止输出 /new。任务完成后必须在当前对话继续工作。")
                override_prompt = "\n".join(override_prompt_parts) if override_prompt_parts else None

                log.info("  [%s@%s] 请求 AI 决策... %s", atype, tty, "(WAKE UP CHECK)" if override_prompt else "")
                decision = call_claude(atype, content, peer_context, override_prompt, tty=tty)

                if decision and decision.strip() == "/new" and not process_cfg.get("new_chat_on_done", True):
                    log.info("  [%s@%s] 配置拦截 /new，改为当前对话继续", atype, tty)
                    decision = "根据白蚁协议，在当前对话继续推进，不要/new。"
                
                # 如果是唤醒检查，且AI决定继续暂停
                if is_waking_up and decision and "[PAUSE]" in decision:
                    log.info("  [%s@%s] 唤醒检查决定继续休息，暂停 %d 秒", atype, tty, PAUSE_DURATION)
                    pause_history[tty] = time.time() + PAUSE_DURATION
                    continue
                
                # 如果决定恢复（没有输出 PAUSE），则清理 pause_history
                if is_waking_up and tty in pause_history:
                    del pause_history[tty]

                if decision:
                    # 记录 AI 指令历史
                    if tty not in ai_decision_history:
                        ai_decision_history[tty] = deque(maxlen=10)
                    ai_decision_history[tty].append(decision)

                    if "[PAUSE]" in decision:
                        log.info("  [%s] AI 请求休息，暂停 %d 秒", atype, PAUSE_DURATION)
                        pause_history[tty] = time.time() + PAUSE_DURATION
                        # 仍记录到历史防止立即重试 (虽然 pause_history 已经处理了)
                        sent_history[tty] = time.time()
                    else:
                        log.info("  [%s] AI 决策发送: '%s'", atype, decision.replace('\n', '\\n'))
                        if inject_input(tty, decision):
                            sent_history[tty] = time.time()
                else:
                    log.warning("  [%s] AI 未返回有效指令", atype)

        except Exception as e:
            log.error("主循环异常: %s", e)
        
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
