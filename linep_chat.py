#!/usr/bin/env python3
"""
LiNeP Interactive Scheduler
============================

Du bist der Scheduler, der Mac (192.168.178.145:9000) ist der Worker.
Tippe Nachrichten ein, wähle den TaskType, und sende sie live ans Modell.
"""

import sys
import time
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "python"))

import linep
from linep import Sender, TaskType, ResultStatus

MAC_HOST  = "192.168.178.145"
MAC_PORT  = 9000
TIMEOUT_MS = 300_000  # 5 Minuten — für komplexe Code-Tasks

TASK_TYPES = {
    "1": TaskType.INSTRUCT,
    "2": TaskType.CODE,
    "3": TaskType.SUMMARIZE,
    "4": TaskType.CLASSIFY,
    "5": TaskType.VALIDATE,
    "6": TaskType.EDGE_TEXT_EVAL,
}

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
GRAY   = "\033[90m"
BLUE   = "\033[94m"


def format_result_body(raw_body: bytes) -> tuple[list[str], str | None]:
    """Parse LiNeP RESULT payload JSON and return text lines plus metadata line.

    Falls back to plain text for legacy workers.
    """
    body = raw_body.decode("utf-8", errors="replace").strip()
    if not body:
        return ["(leer)"], None

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return body.splitlines() or ["(leer)"], None

    if not isinstance(parsed, dict):
        return body.splitlines() or ["(leer)"], None

    text = parsed.get("text", "")
    if isinstance(text, str):
        text_lines = text.splitlines() or ["(leer)"]
    else:
        text_lines = [str(text)]

    meta_parts = []
    model = parsed.get("model")
    latency_ms = parsed.get("latency_ms")
    tokens_in = parsed.get("tokens_in")
    tokens_out = parsed.get("tokens_out")

    if model is not None:
        meta_parts.append(f"model: {model}")
    if latency_ms is not None:
        meta_parts.append(f"latency: {latency_ms}ms")
    if tokens_in is not None:
        meta_parts.append(f"tokens_in: {tokens_in}")
    if tokens_out is not None:
        meta_parts.append(f"tokens_out: {tokens_out}")

    meta_line = f"[{' | '.join(meta_parts)}]" if meta_parts else None
    return text_lines, meta_line


def print_banner():
    print(f"\n{BOLD}{CYAN}")
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║           LiNeP Interactive Scheduler                       ║")
    print(f"║  Scheduler: Windows (hier)   Worker: {MAC_HOST}:{MAC_PORT}  ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(RESET)
    print(f"  {GRAY}Timeout: {TIMEOUT_MS//1000}s pro Task — LLM hat Zeit zum Denken{RESET}\n")


def pick_task_type() -> TaskType:
    print(f"\n{BOLD}TaskType wählen:{RESET}")
    for k, v in TASK_TYPES.items():
        print(f"  {CYAN}{k}{RESET}) {v.name}")
    print(f"  {CYAN}Enter{RESET}) INSTRUCT (default)")

    while True:
        choice = input(f"\n{BOLD}>{RESET} ").strip()
        if choice == "":
            return TaskType.INSTRUCT
        if choice in TASK_TYPES:
            return TASK_TYPES[choice]
        print(f"  {YELLOW}Ungültig — bitte 1-6 oder Enter{RESET}")


def send_and_print(sender: Sender, task_type: TaskType, payload: str, corr_id: int):
    """Sendet einen Task und gibt das Ergebnis live aus."""
    print(f"\n{BOLD}{BLUE}┌─ Sende an {MAC_HOST}:{MAC_PORT} ──────────────────────────────{RESET}")
    print(f"{BLUE}│{RESET} TaskType  : {CYAN}{task_type.name}{RESET}")
    print(f"{BLUE}│{RESET} Payload   : {payload[:100]}{'…' if len(payload) > 100 else ''}")
    print(f"{BLUE}│{RESET} Timeout   : {TIMEOUT_MS // 1000}s")
    print(f"{BOLD}{BLUE}└─ Warte auf Antwort…{RESET}", flush=True)

    t0 = time.monotonic()
    try:
        result = sender.send_task(
            host=MAC_HOST,
            port=MAC_PORT,
            task_type=task_type,
            payload=payload.encode("utf-8"),
            correlation_id=corr_id,
            timeout_ms=TIMEOUT_MS,
        )
        elapsed = (time.monotonic() - t0) * 1000

        status_color = GREEN if result.status == ResultStatus.OK else YELLOW
        print(f"\n{BOLD}{GREEN}┌─ Antwort ({elapsed:.0f} ms) ──────────────────────────────────{RESET}")
        print(f"{GREEN}│{RESET} Status : {status_color}{result.status.name}{RESET}")
        body_lines, meta_line = format_result_body(result.body)
        if meta_line:
            print(f"{GREEN}│{RESET} Meta   : {GRAY}{meta_line}{RESET}")
        print(f"{GREEN}│{RESET}")
        # Print response text with line wrapping.
        for line in body_lines:
            print(f"{GREEN}│{RESET}  {line}")
        print(f"{BOLD}{GREEN}└──────────────────────────────────────────────────────────{RESET}")

    except Exception as e:
        elapsed = (time.monotonic() - t0) * 1000
        print(f"\n{RED}✗ Fehler nach {elapsed:.0f}ms: {e}{RESET}")


def main():
    print_banner()

    linep.net_init()
    sender = Sender()
    corr_id = 0

    print(f"  {GRAY}Befehle: {BOLD}:type{GRAY} — TaskType wechseln  |  {BOLD}:quit{GRAY} — beenden{RESET}")
    print(f"  {GRAY}Einfach Text eingeben und Enter drücken.{RESET}\n")

    current_type = TaskType.INSTRUCT
    print(f"  Aktueller TaskType: {CYAN}{BOLD}{current_type.name}{RESET}\n")

    try:
        while True:
            try:
                user_input = input(f"{BOLD}{CYAN}[{current_type.name}]{RESET} > ").strip()
            except (EOFError, KeyboardInterrupt):
                print(f"\n{GRAY}Tschüss!{RESET}")
                break

            if not user_input:
                continue

            if user_input.lower() in (":quit", ":q", "exit", "quit"):
                print(f"\n{GRAY}Tschüss!{RESET}")
                break

            if user_input.lower() in (":type", ":t"):
                current_type = pick_task_type()
                print(f"\n  TaskType gesetzt: {CYAN}{BOLD}{current_type.name}{RESET}\n")
                continue

            if user_input.startswith(":"):
                print(f"  {YELLOW}Unbekannter Befehl. Bekannte Befehle: :type, :quit{RESET}")
                continue

            corr_id += 1
            send_and_print(sender, current_type, user_input, corr_id)

    finally:
        sender.close()
        linep.net_cleanup()
        print()


if __name__ == "__main__":
    main()
