#!/usr/bin/env python3
"""Offline built-binary and real PTY smoke checks. Never opens provider credentials."""
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time

binary = str(Path(sys.argv[1]).resolve())
repo = Path(__file__).resolve().parent.parent
canary = "KEYRADAR_SMOKE_NEVER_VALID_f42c761"


def run(args, expected=0):
    p = subprocess.run([binary, *args], capture_output=True, timeout=15)
    assert p.returncode == expected, f"unexpected exit for {args[0]}: {p.returncode}"
    assert canary.encode() not in p.stdout + p.stderr, "canary escaped"
    return p.stdout


def terminal_smoke(fixture=None, case=None):
    pid, master = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        args = [binary, "tui"]
        if case is not None:
            args += ["--case", str(case), "--incident", "custom"]
        os.execv(binary, args)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
    started = time.monotonic()
    output = bytearray()
    actions = [(0.6, b"/add\r"), (1.1, b"\x1b[B\r"), (1.5, b"\x1b"), (1.7, b"\x1b"), (1.9, b"/demo\r"), (2.2, b"\t"), (2.5, b"\t"), (2.8, b"\t"), (3.1, b"/quit\r")]
    if fixture is not None:
        actions = [(0.6, b"\r"), (1.0, b"\r"),
                   (1.4, str(fixture).encode() + b"\r"), (1.8, b"\r"),
                   (2.7, b"\t\t"), (3.2, b"/quit\r")]
    reaped = False
    try:
        while time.monotonic() - started < 12:
            elapsed = time.monotonic() - started
            while actions and elapsed >= actions[0][0]:
                os.write(master, actions.pop(0)[1])
            if select.select([master], [], [], 0.05)[0]:
                try:
                    data = os.read(master, 65536)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    data = b""
                output.extend(data)
                # A PTY has no terminal emulator to answer startup capability queries.
                if b"\x1b]11;?" in data:
                    os.write(master, b"\x1b]11;rgb:0000/0000/0000\x1b\\")
                if b"\x1b[6n" in data:
                    os.write(master, b"\x1b[1;1R")
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                reaped = True
                assert os.waitstatus_to_exitcode(status) == 0, "TUI failed"
                break
        assert reaped, "TUI did not exit"
        expected = b"Source added" if fixture is not None else b"Offline synthetic"
        assert b"KeyRadar" in output and expected in output, "TUI did not render workflow"
        field = b"Local .env path" if fixture is not None else b"Vercel team ID"
        assert "█".encode() in output and field in output, "prompt or guided picker missing"
        assert canary.encode() not in output, "source value rendered"
        assert b"KEYRADAR_SYNTHETIC_NEVER_VALID_27d8d9" not in output, "demo material escaped"
    finally:
        os.close(master)
        if not reaped:
            os.kill(pid, 9)
            os.waitpid(pid, 0)


with tempfile.TemporaryDirectory(prefix="keyradar-smoke-") as raw:
    root = Path(raw).resolve()  # macOS /var alias must not bypass symlink rejection.
    fixture = root / "input.env"
    fixture.write_text(f"API_KEY={canary}\n")
    fixture.chmod(0o600)
    case = root / "case"
    args = ["scan", "--incident", "custom", "--local-file", str(fixture), "--case", str(case), "--format", "json", "--shareable"]
    first = json.loads(run(args))
    assert first["shareable"] and len(first["credentials"]) == 1
    fixture.write_text("API_KEY=KEYRADAR_NEW_SYNTHETIC_VALUE\n")
    second = json.loads(run(args))
    assert len(second["credentials"]) == 2, "rescan lost history"
    assert second["credentials"][0]["locations"] == [], "old credential still current"
    assert canary not in (case / "case.json").read_text(), "canary persisted"
    run(["clean", "--case", str(case)])
    demo_case = root / "demo"
    demo = json.loads(run(["demo", "--case", str(demo_case), "--format", "json", "--shareable"], 2))
    assert demo["coverage_status"] == "partial"
    run(["report", "--case", str(demo_case), "--shareable"], 2)
    run(["clean", "--case", str(demo_case)], 1)
    run(["clean", "--case", str(demo_case), "--forget"])
    run(["scan", "--unknown=" + canary], 1)
    for host, destination in [("codex", ".agents"), ("claude-code", ".claude")]:
        installed = root / destination / "skills" / "keyradar"
        shutil.copytree(repo / "integrations" / host / "keyradar", installed)
        for path in ["SKILL.md", "references/report.md", "references/runbooks.md"]:
            assert (installed / path).is_file(), "incomplete skill installation"
    terminal_smoke()
    spaced = root / "input with spaces.env"
    spaced.write_text(f"API_KEY={canary}\n")
    spaced.chmod(0o600)
    tui_case = root / "tui-case"
    terminal_smoke(spaced, tui_case)
    persisted = json.loads(run(["report", "--case", str(tui_case), "--format", "json", "--shareable"]))
    assert len(persisted["credentials"]) == 1, "guided scan was not persisted"
print("PASS: built CLI, redaction, case/rescan/cleanup, skill layout, and offline PTY demo")
