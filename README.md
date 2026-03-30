# proc-signal-dump

Debug tool for dumping signal handlers and dispositions from running Linux processes.

## Why I wrote this

Ever had a process that just won't die when you send SIGTERM? Or maybe signals are getting swallowed somewhere and you can't figure out why? This tool reads `/proc/[pid]/status` to show you exactly what's going on with signal handling in any process you can access.

## What it does

- Shows signal disposition (default/ignored/custom handler) for all signals
- Displays which signals are blocked per-process
- Shows pending signals waiting to be delivered
- Optional thread-level signal mask inspection
- Lists processes with custom signal handlers
- JSON output format for programmatic use

## Usage

```bash
# Inspect a specific process
python3 proc_signal_dump.py <pid>

# Inspect current shell
python3 proc_signal_dump.py --self

# List all processes
python3 proc_signal_dump.py --list

# Find processes matching a pattern
python3 proc_signal_dump.py --list --pattern python

# Verbose mode with thread info
python3 proc_signal_dump.py <pid> -v

# JSON output
python3 proc_signal_dump.py <pid> --json

# JSON output with thread info
python3 proc_signal_dump.py <pid> --json -v
```

## Example output

```
Process: 1234
Name: myapp
State: S (sleeping)
Command: python3 myapp.py --config prod.yaml

Signal Dispositions:
------------------------------------------------------------
Signal       Disposition  Blocked    Pending
------------------------------------------------------------
SIGINT       handler      no         no
SIGTERM      handler      no         no
SIGCHLD      handler      no         no
SIGPIPE      ignore       no         no
SIGUSR1      handler      yes        no

Custom handlers installed: SIGINT, SIGTERM, SIGCHLD, SIGUSR1
Signals ignored: SIGPIPE
```

## JSON output example

```json
{
  "process": {
    "pid": 1234,
    "name": "myapp",
    "state": "S (sleeping)",
    "command": "python3 myapp.py --config prod.yaml"
  },
  "signals": [
    {
      "signal": "SIGINT",
      "number": 2,
      "disposition": "handler",
      "blocked": false,
      "pending": false
    }
  ],
  "summary": {
    "custom_handlers": ["SIGINT", "SIGTERM", "SIGCHLD", "SIGUSR1"],
    "ignored": ["SIGPIPE"]
  }
}
```

## How it works

Reads these fields from `/proc/[pid]/status`:

- `SigCgt` - Signals with custom handlers
- `SigIgn` - Signals being ignored
- `SigBlk` - Blocked signals (masked)
- `SigPnd` - Pending signals

The signal masks are in hex format, one bit per signal. I parse those and map them to actual signal names.

## Requirements

- Python 3.6+
- Linux (uses procfs)
- Read access to /proc/[pid]/status

## Notes

- Need appropriate permissions to inspect other processes
- Some signals like SIGKILL and SIGSTOP can never be caught or ignored
- Thread-level info requires reading `/proc/[pid]/task/[tid]/status`

## License

MIT - do whatever you want with it.
