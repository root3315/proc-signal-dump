#!/usr/bin/env python3
"""
proc-signal-dump - Dump process signal handlers and dispositions for debugging.

Reads signal handler information from /proc/[pid]/status and related procfs
entries to help debug signal handling issues in running processes.
"""

import argparse
import json
import os
import re
import signal
import sys
import time
from pathlib import Path


SIGNAL_NAMES = {
    1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
    5: "SIGTRAP", 6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE",
    9: "SIGKILL", 10: "SIGUSR1", 11: "SIGSEGV", 12: "SIGUSR2",
    13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 16: "SIGSTKFLT",
    17: "SIGCHLD", 18: "SIGCONT", 19: "SIGSTOP", 20: "SIGTSTP",
    21: "SIGTTIN", 22: "SIGTTOU", 23: "SIGURG", 24: "SIGXCPU",
    25: "SIGXFSZ", 26: "SIGVTALRM", 27: "SIGPROF", 28: "SIGWINCH",
    29: "SIGIO", 30: "SIGPWR", 31: "SIGSYS",
}

SIG_DFL = 0
SIG_IGN = 1
SIG_HANDLER_CUSTOM = 2

DEFAULT_RETRIES = 3
DEFAULT_RETRY_DELAY = 0.1


def get_signal_name(signum):
    """Return signal name for a given signal number."""
    return SIGNAL_NAMES.get(signum, f"SIG{signum}")


def parse_sig_mask(mask_str):
    """Parse a signal mask from hex string to set of signal numbers."""
    try:
        mask = int(mask_str, 16)
    except ValueError:
        return set()

    signals = set()
    for bit in range(1, 65):
        if mask & (1 << (bit - 1)):
            signals.add(bit)
    return signals


def read_proc_file_with_retry(path, retries=DEFAULT_RETRIES, delay=DEFAULT_RETRY_DELAY):
    """Read a proc file with retry logic for transient access failures."""
    last_error = None
    
    for attempt in range(retries):
        try:
            with open(path, "r") as f:
                return f.read()
        except (PermissionError, ProcessLookupError, FileNotFoundError) as e:
            last_error = e
            if attempt < retries - 1:
                time.sleep(delay)
        except OSError as e:
            last_error = e
            if attempt < retries - 1:
                time.sleep(delay)
    
    return None


def read_proc_status(pid, retries=DEFAULT_RETRIES, delay=DEFAULT_RETRY_DELAY):
    """Read and parse /proc/[pid]/status file."""
    status_path = Path(f"/proc/{pid}/status")
    
    content = read_proc_file_with_retry(status_path, retries, delay)
    if content is None:
        return None

    status = {}
    for line in content.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key.strip()] = value.strip()

    return status


def read_proc_task_status(pid, retries=DEFAULT_RETRIES, delay=DEFAULT_RETRY_DELAY):
    """Read signal handler info from /proc/[pid]/task/[tid]/status for all threads."""
    task_dir = Path(f"/proc/{pid}/task")
    if not task_dir.exists():
        return []

    threads = []
    try:
        for task_entry in task_dir.iterdir():
            if not task_entry.name.isdigit():
                continue

            tid = int(task_entry.name)
            task_status_path = Path(f"/proc/{pid}/task/{tid}/status")
            content = read_proc_file_with_retry(task_status_path, retries, delay)
            
            if content:
                task_status = {}
                for line in content.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        task_status[key.strip()] = value.strip()
                
                threads.append({
                    "tid": tid,
                    "name": task_status.get("Name", "unknown"),
                    "sig_mask": task_status.get("SigBlk", "0"),
                    "sig_pending": task_status.get("SigPnd", "0"),
                    "sig_ignore": task_status.get("SigIgn", "0"),
                    "sig_catch": task_status.get("SigCgt", "0"),
                })
    except (PermissionError, ProcessLookupError) as e:
        print(f"Error reading task status: {e}", file=sys.stderr)

    return threads


def read_proc_cmdline(pid, retries=DEFAULT_RETRIES, delay=DEFAULT_RETRY_DELAY):
    """Read command line for a process."""
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    
    content = read_proc_file_with_retry(cmdline_path, retries, delay)
    if content is None:
        return "<unknown>"
    
    return content.replace("\x00", " ").strip()


def analyze_signal_disposition(sig_catch, sig_ignore, signum):
    """Determine signal disposition based on SigCgt and SigIgn masks."""
    catch_mask = parse_sig_mask(sig_catch)
    ignore_mask = parse_sig_mask(sig_ignore)

    if signum in catch_mask:
        return SIG_HANDLER_CUSTOM
    elif signum in ignore_mask:
        return SIG_IGN
    else:
        return SIG_DFL


def format_disposition(disposition):
    """Format signal disposition for display."""
    if disposition == SIG_DFL:
        return "default"
    elif disposition == SIG_IGN:
        return "ignore"
    else:
        return "handler"


def dump_process_signals(pid, verbose=False, json_output=False):
    """Dump signal information for a given process."""
    status = read_proc_status(pid)
    if not status:
        print(f"Cannot access process {pid}", file=sys.stderr)
        return False

    cmdline = read_proc_cmdline(pid)
    proc_name = status.get("Name", "<unknown>")
    state = status.get("State", "?")

    sig_catch = status.get("SigCgt", "0")
    sig_ignore = status.get("SigIgn", "0")
    sig_mask = status.get("SigBlk", "0")
    sig_pending = status.get("SigPnd", "0")

    catch_set = parse_sig_mask(sig_catch)
    ignore_set = parse_sig_mask(sig_ignore)
    blocked_set = parse_sig_mask(sig_mask)
    pending_set = parse_sig_mask(sig_pending)

    if json_output:
        return dump_process_signals_json(
            pid, proc_name, state, cmdline,
            sig_catch, sig_ignore, sig_mask, sig_pending,
            catch_set, ignore_set, blocked_set, pending_set,
            verbose
        )

    print(f"Process: {pid}")
    print(f"Name: {proc_name}")
    print(f"State: {state}")
    print(f"Command: {cmdline}")
    print()

    print("Signal Dispositions:")
    print("-" * 60)
    print(f"{'Signal':<12} {'Disposition':<12} {'Blocked':<10} {'Pending':<10}")
    print("-" * 60)

    for signum in sorted(SIGNAL_NAMES.keys()):
        sig_name = get_signal_name(signum)
        disposition = analyze_signal_disposition(sig_catch, sig_ignore, signum)
        disp_str = format_disposition(disposition)
        blocked_str = "yes" if signum in blocked_set else "no"
        pending_str = "yes" if signum in pending_set else "no"

        if disposition != SIG_DFL or blocked_set or pending_set or verbose:
            print(f"{sig_name:<12} {disp_str:<12} {blocked_str:<10} {pending_str:<10}")

    print()

    if verbose:
        print("Thread-level Signal Masks:")
        print("-" * 60)
        threads = read_proc_task_status(pid)
        if threads:
            for thread in threads:
                print(f"Thread {thread['tid']} ({thread['name']}):")
                t_blocked = parse_sig_mask(thread["sig_mask"])
                t_pending = parse_sig_mask(thread["sig_pending"])
                if t_blocked:
                    blocked_names = [get_signal_name(s) for s in sorted(t_blocked)]
                    print(f"  Blocked: {', '.join(blocked_names)}")
                if t_pending:
                    pending_names = [get_signal_name(s) for s in sorted(t_pending)]
                    print(f"  Pending: {', '.join(pending_names)}")
        print()

    handlers_installed = [get_signal_name(s) for s in sorted(catch_set) if s in SIGNAL_NAMES]
    handlers_ignored = [get_signal_name(s) for s in sorted(ignore_set) if s in SIGNAL_NAMES]

    if handlers_installed:
        print(f"Custom handlers installed: {', '.join(handlers_installed)}")
    if handlers_ignored:
        print(f"Signals ignored: {', '.join(handlers_ignored)}")

    return True


def dump_process_signals_json(
    pid, proc_name, state, cmdline,
    sig_catch, sig_ignore, sig_mask, sig_pending,
    catch_set, ignore_set, blocked_set, pending_set,
    verbose
):
    """Output signal information in JSON format."""
    signals = []
    for signum in sorted(SIGNAL_NAMES.keys()):
        sig_name = get_signal_name(signum)
        disposition = analyze_signal_disposition(sig_catch, sig_ignore, signum)
        disp_str = format_disposition(disposition)
        signals.append({
            "signal": sig_name,
            "number": signum,
            "disposition": disp_str,
            "blocked": signum in blocked_set,
            "pending": signum in pending_set,
        })

    result = {
        "process": {
            "pid": pid,
            "name": proc_name,
            "state": state,
            "command": cmdline,
        },
        "signals": signals,
        "summary": {
            "custom_handlers": [get_signal_name(s) for s in sorted(catch_set) if s in SIGNAL_NAMES],
            "ignored": [get_signal_name(s) for s in sorted(ignore_set) if s in SIGNAL_NAMES],
        }
    }

    if verbose:
        threads = read_proc_task_status(pid)
        thread_data = []
        for thread in threads:
            t_blocked = parse_sig_mask(thread["sig_mask"])
            t_pending = parse_sig_mask(thread["sig_pending"])
            thread_info = {
                "tid": thread["tid"],
                "name": thread["name"],
            }
            if t_blocked:
                thread_info["blocked"] = [get_signal_name(s) for s in sorted(t_blocked)]
            if t_pending:
                thread_info["pending"] = [get_signal_name(s) for s in sorted(t_pending)]
            thread_data.append(thread_info)
        result["threads"] = thread_data

    print(json.dumps(result, indent=2))
    return True


def list_processes(pattern=None):
    """List processes matching optional pattern."""
    processes = []
    proc_dir = Path("/proc")

    for entry in proc_dir.iterdir():
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)
        try:
            cmdline = read_proc_cmdline(pid)
            status = read_proc_status(pid)
            if status:
                name = status.get("Name", "<unknown>")
                if pattern is None or pattern.lower() in name.lower() or pattern.lower() in cmdline.lower():
                    processes.append((pid, name, cmdline))
        except (PermissionError, ProcessLookupError):
            continue

    return processes


def main():
    parser = argparse.ArgumentParser(
        description="Dump process signal handlers and dispositions for debugging"
    )
    parser.add_argument(
        "pid",
        nargs="?",
        type=int,
        help="Process ID to inspect"
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all processes with signal handlers"
    )
    parser.add_argument(
        "-p", "--pattern",
        type=str,
        help="Filter processes by name pattern (use with --list)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show thread-level signal information"
    )
    parser.add_argument(
        "--self",
        action="store_true",
        help="Inspect current process"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    args = parser.parse_args()

    if args.self:
        args.pid = os.getpid()

    if args.list:
        processes = list_processes(args.pattern)
        if not processes:
            print("No matching processes found")
            return 0

        print(f"{'PID':<10} {'Name':<20} {'Command'}")
        print("-" * 70)
        for pid, name, cmdline in sorted(processes):
            cmdline_display = cmdline[:50] + "..." if len(cmdline) > 50 else cmdline
            print(f"{pid:<10} {name:<20} {cmdline_display}")
        return 0

    if args.pid is None:
        parser.print_help()
        return 1

    if not dump_process_signals(args.pid, args.verbose, args.json):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
