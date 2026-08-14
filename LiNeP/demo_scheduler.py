#!/usr/bin/env python3
"""
LiNeP Demo Scheduler
====================

Ich (Windows) bin der Scheduler.
Der Mac (192.168.178.145) ist der Worker.

Sendet INSTRUCT-Tasks an beide Worker-Slots und zeigt die Ergebnisse.
"""

import sys
import time
import threading
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "python"))

import linep
from linep import Sender, TaskType, ResultStatus

MAC_HOST = "192.168.178.145"
WORKERS = [
    {"port": 9000, "name": "Worker-Slot-0"},
]


class Colors:
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def send_task(worker: dict, task_type: TaskType, payload: bytes, corr_id: int = 0) -> None:
    """Send one task to a worker and print the result."""
    port = worker["port"]
    name = worker["name"]
    sender = Sender()
    try:
        print(f"\n{Colors.CYAN}[Scheduler → {name} @ {MAC_HOST}:{port}]{Colors.RESET}")
        print(f"  TaskType : {task_type.name}")
        print(f"  Payload  : {payload.decode('utf-8', errors='replace')[:80]}")

        t0 = time.monotonic()
        result = sender.send_task(
            host=MAC_HOST,
            port=port,
            task_type=task_type,
            payload=payload,
            correlation_id=corr_id,
            timeout_ms=10_000,
        )
        elapsed = (time.monotonic() - t0) * 1000

        status_color = Colors.GREEN if result.status == ResultStatus.OK else Colors.YELLOW
        print(f"  Status   : {status_color}{result.status.name}{Colors.RESET}  ({elapsed:.0f} ms)")
        print(f"  Response : {result.body.decode('utf-8', errors='replace')[:200]}")

    except Exception as e:
        print(f"  {Colors.RED}ERROR: {e}{Colors.RESET}")
    finally:
        sender.close()


def run_sequential(tasks: list[tuple]):
    """Send tasks to workers one after the other."""
    print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Sequential mode — {len(tasks)} task(s){Colors.RESET}")
    print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")
    for i, (worker, task_type, payload) in enumerate(tasks):
        send_task(worker, task_type, payload, corr_id=i)


def run_parallel(tasks: list[tuple]):
    """Send all tasks to both workers in parallel."""
    print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Parallel mode — {len(tasks)} task(s) → both workers simultaneously{Colors.RESET}")
    print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}")
    threads = []
    for i, (worker, task_type, payload) in enumerate(tasks):
        t = threading.Thread(target=send_task, args=(worker, task_type, payload, i))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main():
    parser = argparse.ArgumentParser(description="LiNeP Demo Scheduler → Mac Worker")
    parser.add_argument("--parallel", action="store_true", help="Send to both workers in parallel")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat all tasks N times")
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}{Colors.CYAN}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        LiNeP Demo Scheduler (Windows → Mac)             ║")
    print(f"║  Worker: {MAC_HOST}  Ports: 9000, 9001            ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(Colors.RESET)

    linep.net_init()

    # Tasks to send
    task_batches = [
        (WORKERS[0], TaskType.INSTRUCT,  b"Was ist 6 mal 7?"),
        (WORKERS[0], TaskType.SUMMARIZE, b"LiNeP ist ein leichtgewichtiges Netzwerkprotokoll fuer KI-Modelle."),
        (WORKERS[0], TaskType.CODE,      b"def fibonacci(n): ..."),
        (WORKERS[0], TaskType.CLASSIFY,  b"Das Wetter heute ist sonnig und warm."),
    ]

    try:
        for run in range(args.repeat):
            if args.repeat > 1:
                print(f"\n{Colors.YELLOW}--- Run {run + 1}/{args.repeat} ---{Colors.RESET}")

            if args.parallel:
                run_parallel(task_batches)
            else:
                run_sequential(task_batches)

            if run < args.repeat - 1:
                time.sleep(0.5)

    finally:
        linep.net_cleanup()

    print(f"\n{Colors.GREEN}{Colors.BOLD}Done.{Colors.RESET}\n")


if __name__ == "__main__":
    main()
