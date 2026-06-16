"""
WSLGuardian - Lightweight WSL Threat Monitoring Service

Academic proof-of-concept for monitoring Windows Subsystem for Linux (WSL)
activity from the Windows host. The service detects predefined suspicious
command patterns, attempts to terminate the related WSL process, and records
text + JSONL logs for later review or SIEM ingestion.

Project: NEXUS GUARD / WSLGuardian
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Thread
from typing import Dict, Iterable, Optional, Tuple

import psutil

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:  # Allows --test to run even when pywin32 is unavailable.
    servicemanager = None
    win32event = None
    win32service = None
    win32serviceutil = None

APP_NAME = "WSLGuardian"
SERVICE_NAME = "WSLGuardian"
SERVICE_DISPLAY_NAME = "WSL Guardian Service"
SERVICE_DESCRIPTION = "Monitors WSL for unauthorized commands and terminates flagged sessions."

PROGRAM_DATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
LOG_DIR = PROGRAM_DATA / APP_NAME
TEXT_LOG_FILE = LOG_DIR / "wsl_guardian.log"
JSON_LOG_FILE = LOG_DIR / "events.jsonl"
DETAILED_LOG_DIR = LOG_DIR / "detailed_logs"

POLL_INTERVAL_SECONDS = 1.0
IDLE_INTERVAL_SECONDS = 2.0

# Demo detection rules. Tune these rules before production use.
UNAUTHORIZED_COMMANDS = [
    {"name": "nmap", "pattern": r"\bnmap\b"},
    {"name": "nc", "pattern": r"\bnc\b"},
    {"name": "netcat", "pattern": r"\bnetcat\b"},
    {"name": "curl", "pattern": r"\bcurl\b"},
    {"name": "wget", "pattern": r"\bwget\b"},
    {"name": "tcpdump", "pattern": r"\btcpdump\b"},
    {"name": "wireshark", "pattern": r"\bwireshark\b"},
    {"name": "hashcat", "pattern": r"\bhashcat\b"},
    {"name": "hydra", "pattern": r"\bhydra\b"},
    {"name": "john", "pattern": r"\bjohn\s+\w+\b"},
    {"name": "mimikatz", "pattern": r"\bmimikatz\b"},
    {"name": "crackmapexec", "pattern": r"\bcrackmapexec\b"},
    {"name": "metasploit", "pattern": r"\bmetasploit\b"},
    {"name": "msfconsole", "pattern": r"\bmsfconsole\b"},
    {"name": "msfvenom", "pattern": r"\bmsfvenom\b"},
    {"name": "powershell encoded command", "pattern": r"\bpowershell(?:\.exe)?\s+(-|/)e(?:ncodedcommand)?\b"},
    {"name": "base64 decode", "pattern": r"\bbase64\s+(-d|--decode)\b"},
    {"name": "certutil decode", "pattern": r"\bcertutil\s+(-decode|-decodehex)\b"},
]

COMPILED_RULES = [
    {"name": rule["name"], "regex": re.compile(rule["pattern"], re.IGNORECASE)}
    for rule in UNAUTHORIZED_COMMANDS
]


def ensure_log_directories() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    DETAILED_LOG_DIR.mkdir(parents=True, exist_ok=True)


def configure_logging() -> logging.Logger:
    ensure_log_directories()

    logger = logging.getLogger("wsl_guardian")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = logging.FileHandler(TEXT_LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


logger = configure_logging()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class WSLGuardian:
    """Main monitoring and response engine."""

    def __init__(self, allow_global_shutdown: bool = True) -> None:
        self.wsl_processes: Dict[int, Dict[str, object]] = {}
        self.running = False
        self.stop_event = Event()
        self.allow_global_shutdown = allow_global_shutdown

        logger.info("WSL Guardian initialized")
        logger.info("Monitoring for %s unauthorized commands", len(UNAUTHORIZED_COMMANDS))
        self.log_event("service_initialized", details={"rule_count": len(UNAUTHORIZED_COMMANDS)})

    def log_event(self, event_type: str, **fields: object) -> None:
        """Write a SIEM-friendly JSONL event."""
        event = {
            "timestamp": utc_now(),
            "event_type": event_type,
            **fields,
        }
        try:
            with JSON_LOG_FILE.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.error("Unable to write JSON event log: %s", exc)

    def log_detailed(self, pid: int, message: str) -> None:
        """Write process-specific diagnostics."""
        try:
            log_file = DETAILED_LOG_DIR / f"wsl_process_{pid}.log"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with log_file.open("a", encoding="utf-8") as handle:
                handle.write(f"[{timestamp}] {message}\n")
        except OSError as exc:
            logger.error("Error writing detailed log for PID %s: %s", pid, exc)

    @staticmethod
    def check_for_unauthorized_commands(text: str) -> Tuple[bool, Optional[str]]:
        """Return True and the rule name when text matches a detection rule."""
        if not text:
            return False, None

        for rule in COMPILED_RULES:
            if rule["regex"].search(text):
                return True, str(rule["name"])
        return False, None

    @staticmethod
    def run_command(command: Iterable[str], timeout: int = 10) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def terminate_wsl(self, pid: int, reason: str) -> bool:
        """Attempt to terminate a flagged Windows-visible WSL process."""
        logger.warning("TERMINATING WSL [%s] - Reason: %s", pid, reason)
        self.log_detailed(pid, f"TERMINATION TRIGGERED: {reason}")
        self.log_event("termination_triggered", pid=pid, reason=reason)

        # Method 1: taskkill, which is reliable on Windows.
        if os.name == "nt":
            try:
                result = self.run_command(["taskkill", "/F", "/PID", str(pid)], timeout=10)
                if result.returncode == 0:
                    logger.info("Successfully terminated process %s using taskkill", pid)
                    self.log_event("termination_success", pid=pid, method="taskkill", reason=reason)
                    return True
                logger.warning("taskkill failed for PID %s: %s", pid, result.stderr.strip())
            except Exception as exc:  # noqa: BLE001 - service must not crash on termination errors.
                logger.warning("Error with taskkill for PID %s: %s", pid, exc)

        # Method 2: psutil terminate/kill.
        try:
            process = psutil.Process(pid)
            process.terminate()
            try:
                process.wait(timeout=3)
            except psutil.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            logger.info("Successfully terminated process %s using psutil", pid)
            self.log_event("termination_success", pid=pid, method="psutil", reason=reason)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error with psutil termination for PID %s: %s", pid, exc)

        # Method 3: signal fallback.
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
            if psutil.pid_exists(pid) and hasattr(signal, "SIGKILL"):
                os.kill(pid, signal.SIGKILL)
            logger.info("Successfully terminated process %s using signal", pid)
            self.log_event("termination_success", pid=pid, method="signal", reason=reason)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Signal termination failed for PID %s: %s", pid, exc)

        # Final fallback: shut down WSL entirely. This is intentionally logged as a global action.
        if self.allow_global_shutdown and os.name == "nt":
            try:
                result = self.run_command(["wsl", "--shutdown"], timeout=15)
                logger.info("Executed 'wsl --shutdown' as final termination attempt")
                self.log_event(
                    "termination_global_shutdown",
                    pid=pid,
                    reason=reason,
                    return_code=result.returncode,
                )
                return result.returncode == 0
            except Exception as exc:  # noqa: BLE001
                logger.error("Error with wsl --shutdown: %s", exc)

        self.log_event("termination_failed", pid=pid, reason=reason)
        return False

    def find_wsl_processes(self) -> Dict[int, Dict[str, object]]:
        """Find Windows-visible WSL-related processes."""
        current_processes: Dict[int, Dict[str, object]] = {}

        for proc in psutil.process_iter(["pid", "name", "cmdline", "username", "create_time"]):
            try:
                proc_name = (proc.info.get("name") or "").lower()
                if "wsl" not in proc_name and "bash" not in proc_name and "ubuntu" not in proc_name:
                    continue

                pid = int(proc.info["pid"])
                cmdline_list = proc.info.get("cmdline") or []
                cmdline = " ".join(cmdline_list)

                current_processes[pid] = {
                    "pid": pid,
                    "name": proc.info.get("name"),
                    "cmdline": cmdline,
                    "username": proc.info.get("username"),
                    "create_time": proc.info.get("create_time"),
                    "first_seen": self.wsl_processes.get(pid, {}).get("first_seen", datetime.now()),
                    "last_checked": datetime.now(),
                }

                if pid not in self.wsl_processes:
                    logger.info("New WSL process detected: PID=%s, CMD=%s", pid, cmdline)
                    self.log_detailed(pid, f"Process started: {cmdline}")
                    self.log_event(
                        "wsl_process_detected",
                        pid=pid,
                        name=proc.info.get("name"),
                        cmdline=cmdline,
                        username=proc.info.get("username"),
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        for pid in list(self.wsl_processes.keys()):
            if pid not in current_processes:
                logger.info("WSL process terminated: PID=%s", pid)
                self.log_detailed(pid, "Process terminated")
                self.log_event("wsl_process_terminated", pid=pid)

        self.wsl_processes = current_processes
        return current_processes

    def inspect_wsl_process_list(self, host_pid: int) -> bool:
        """Inspect Linux-side process list through WSL when WSL is already running."""
        try:
            result = self.run_command(["wsl", "ps", "-eo", "pid,ppid,user,comm,args"], timeout=10)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Unable to inspect WSL process list: %s", exc)
            return False

        output = (result.stdout or "").lower()
        if result.returncode != 0 or len(output) < 5:
            return False

        self.log_detailed(host_pid, f"WSL process list:\n{output}")
        found, rule_name = self.check_for_unauthorized_commands(output)
        if found:
            logger.warning("Unauthorized command detected: %s", rule_name)
            self.log_event("rule_matched", pid=host_pid, rule=rule_name, source="wsl_process_list")
            self.terminate_wsl(host_pid, f"Unauthorized command: {rule_name}")
            return True
        return False

    def inspect_shell_history(self, host_pid: int) -> bool:
        """Inspect recent bash/zsh history as an additional demo signal."""
        history_command = (
            "for f in ~/.bash_history ~/.zsh_history; do "
            "[ -f \"$f\" ] && tail -n 20 \"$f\"; "
            "done"
        )
        try:
            result = self.run_command(["wsl", "sh", "-lc", history_command], timeout=10)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Unable to inspect WSL shell history: %s", exc)
            return False

        history = (result.stdout or "").lower()
        if result.returncode != 0 or len(history) < 5:
            return False

        self.log_detailed(host_pid, f"Recent shell history:\n{history}")
        for line in history.splitlines()[-20:]:
            found, rule_name = self.check_for_unauthorized_commands(line)
            if found:
                logger.warning("Unauthorized command in history: %s", line)
                self.log_event(
                    "rule_matched",
                    pid=host_pid,
                    rule=rule_name,
                    source="shell_history",
                    command=line,
                )
                self.terminate_wsl(host_pid, f"Unauthorized command in history: {rule_name}")
                return True
        return False

    def check_process_commands(self, pid: int, cmdline: str) -> bool:
        """Check host command line, Linux process list, and recent history."""
        found, rule_name = self.check_for_unauthorized_commands(cmdline.lower())
        if found:
            logger.warning("Unauthorized host command detected: %s", rule_name)
            self.log_event("rule_matched", pid=pid, rule=rule_name, source="host_cmdline", command=cmdline)
            self.terminate_wsl(pid, f"Unauthorized host command: {rule_name}")
            return True

        if self.inspect_wsl_process_list(pid):
            return True

        return self.inspect_shell_history(pid)

    def monitor_wsl(self) -> None:
        logger.info("Starting WSL monitoring")
        self.log_event("monitoring_started")

        while not self.stop_event.is_set():
            try:
                processes = self.find_wsl_processes()

                if not processes:
                    time.sleep(IDLE_INTERVAL_SECONDS)
                    continue

                for pid, info in processes.items():
                    if self.stop_event.is_set():
                        break
                    self.check_process_commands(pid, str(info.get("cmdline") or ""))

                time.sleep(POLL_INTERVAL_SECONDS)

            except Exception as exc:  # noqa: BLE001
                logger.error("[Monitoring Error] %s", exc)
                self.log_event("monitoring_error", error=str(exc))
                time.sleep(5)

        logger.info("WSL monitoring stopped")
        self.log_event("monitoring_stopped")

    def start(self) -> Thread:
        logger.info("Starting WSL Guardian")
        self.stop_event.clear()
        self.running = True

        monitor_thread = Thread(target=self.monitor_wsl, name="WSLGuardianMonitor", daemon=True)
        monitor_thread.start()
        return monitor_thread

    def stop(self) -> None:
        logger.info("Stopping WSL Guardian")
        self.stop_event.set()
        self.running = False


if win32serviceutil is not None:

    class WSLGuardianService(win32serviceutil.ServiceFramework):
        """Windows Service wrapper for WSLGuardian."""

        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.service_stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.guardian = WSLGuardian()
            self.monitor_thread: Optional[Thread] = None

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.service_stop_event)
            self.guardian.stop()
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)

        def SvcDoRun(self) -> None:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self.monitor_thread = self.guardian.start()
            win32event.WaitForSingleObject(self.service_stop_event, win32event.INFINITE)

else:
    WSLGuardianService = None


def require_windows_service_support() -> bool:
    if os.name != "nt":
        print("Windows service mode is only supported on Windows.")
        return False
    if win32serviceutil is None:
        print("pywin32 is required for service mode. Install it with: pip install pywin32")
        return False
    return True


def run_pattern_tests() -> None:
    print("Testing command detection patterns...\n")
    test_strings = [
        "ls -la",
        "cd /etc",
        "grep -r password",
        "nmap 192.168.1.1",
        "nc -lvp 4444",
        "curl -X POST http://example.local",
        "python3 manage.py runserver",
        "hostname",
        "base64 --decode payload.txt",
    ]

    for test in test_strings:
        found, rule_name = WSLGuardian.check_for_unauthorized_commands(test)
        status = "BLOCKED" if found else "ALLOWED"
        suffix = f" detected as {rule_name}" if found else ""
        print(f"{status:7} | {test}{suffix}")


def run_debug_mode(no_shutdown: bool) -> None:
    print("Starting WSLGuardian in console/debug mode")
    print(f"Text log: {TEXT_LOG_FILE}")
    print(f"JSONL log: {JSON_LOG_FILE}")
    print(f"Rules: {len(UNAUTHORIZED_COMMANDS)}")
    print("Press Ctrl+C to stop\n")

    guardian = WSLGuardian(allow_global_shutdown=not no_shutdown)
    guardian.start()

    try:
        while guardian.running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping WSLGuardian...")
        guardian.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="WSLGuardian - Monitor WSL for unauthorized commands")
    parser.add_argument("--install", action="store_true", help="Install as a Windows service")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall the Windows service")
    parser.add_argument("--start", action="store_true", help="Start the Windows service")
    parser.add_argument("--stop", action="store_true", help="Stop the Windows service")
    parser.add_argument("--debug", action="store_true", help="Run in console/debug mode")
    parser.add_argument("--test", action="store_true", help="Test detection patterns")
    parser.add_argument(
        "--no-shutdown",
        action="store_true",
        help="Disable final fallback action that runs 'wsl --shutdown'",
    )
    args = parser.parse_args()

    if args.test:
        run_pattern_tests()
        return

    if args.debug:
        run_debug_mode(no_shutdown=args.no_shutdown)
        return

    if args.install:
        if not require_windows_service_support():
            return
        win32serviceutil.InstallService(
            pythonClassString="wsl_guardian_service.WSLGuardianService",
            serviceName=SERVICE_NAME,
            displayName=SERVICE_DISPLAY_NAME,
            description=SERVICE_DESCRIPTION,
            startType=win32service.SERVICE_AUTO_START,
        )
        print("WSLGuardian service installed successfully.")
        print(f"Logs will be written to: {TEXT_LOG_FILE}")
        return

    if args.uninstall:
        if not require_windows_service_support():
            return
        win32serviceutil.RemoveService(SERVICE_NAME)
        print("WSLGuardian service uninstalled successfully.")
        return

    if args.start:
        if not require_windows_service_support():
            return
        win32serviceutil.StartService(SERVICE_NAME)
        print("WSLGuardian service started successfully.")
        return

    if args.stop:
        if not require_windows_service_support():
            return
        win32serviceutil.StopService(SERVICE_NAME)
        print("WSLGuardian service stopped successfully.")
        return

    parser.print_help()


if __name__ == "__main__":
    main()
