"""
Platform detection + system info gathering (used by Dashboard tab).
"""
import platform
import socket
import time
import subprocess
import os

try:
    import psutil
except ImportError:
    psutil = None


def get_os():
    """Return 'windows', 'linux', or 'other'."""
    sys_name = platform.system().lower()
    if "windows" in sys_name:
        return "windows"
    if "linux" in sys_name:
        return "linux"
    return "other"


def is_admin():
    """Best-effort check whether the process has elevated privileges."""
    try:
        if get_os() == "windows":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def _format_uptime(seconds):
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def get_system_summary():
    """
    Returns a dict of neofetch-style system info.
    Falls back gracefully if psutil isn't available.
    """
    info = {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "hostname": socket.gethostname(),
        "machine": platform.machine(),
        "processor": platform.processor() or "Unknown",
        "python_version": platform.python_version(),
        "admin": is_admin(),
        "uptime": "Unknown",
        "cpu_percent": "N/A",
        "cpu_cores": "N/A",
        "ram_total_gb": "N/A",
        "ram_used_percent": "N/A",
        "ip_address": "Unknown",
        "process_count": "N/A",
    }

    try:
        info["ip_address"] = socket.gethostbyname(socket.gethostname())
    except Exception:
        pass

    if psutil:
        try:
            boot_ts = psutil.boot_time()
            info["uptime"] = _format_uptime(time.time() - boot_ts)
        except Exception:
            pass
        try:
            info["cpu_percent"] = f"{psutil.cpu_percent(interval=0.3)}%"
            info["cpu_cores"] = psutil.cpu_count(logical=True)
        except Exception:
            pass
        try:
            vm = psutil.virtual_memory()
            info["ram_total_gb"] = round(vm.total / (1024 ** 3), 1)
            info["ram_used_percent"] = f"{vm.percent}%"
        except Exception:
            pass
        try:
            info["process_count"] = len(psutil.pids())
        except Exception:
            pass

    return info


def run_command(command, shell=True, timeout=15):
    """
    Run a read-only-intent shell command and capture output.
    Returns (success, output_text).
    Never raises - all errors are captured and returned as text.
    """
    try:
        result = subprocess.run(
            command,
            shell=shell,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout or ""
        if result.stderr:
            output += ("\n[stderr]\n" + result.stderr)
        return (result.returncode == 0, output.strip() or "(no output)")
    except subprocess.TimeoutExpired:
        return (False, f"[!] Command timed out after {timeout}s")
    except FileNotFoundError:
        return (False, "[!] Command not found on this system")
    except Exception as e:
        return (False, f"[!] Error running command: {e}")


def open_native_tool(name):
    """
    Open an OS-native tool by logical name.
    name: one of 'task_manager', 'services', 'event_viewer',
          'task_scheduler', 'registry_editor', 'resource_monitor'
    """
    os_name = get_os()
    try:
        if os_name == "windows":
            mapping = {
                "task_manager": "taskmgr",
                "services": "services.msc",
                "event_viewer": "eventvwr.msc",
                "task_scheduler": "taskschd.msc",
                "registry_editor": "regedit",
                "resource_monitor": "resmon",
            }
            cmd = mapping.get(name)
            if not cmd:
                return False, f"Unknown tool: {name}"
            subprocess.Popen(f"start {cmd}", shell=True)
            return True, f"Opened {cmd}"
        elif os_name == "linux":
            mapping = {
                "task_manager": ["gnome-system-monitor", "xterm -e htop", "xterm -e top"],
                "services": ["xterm -e 'systemctl status; bash'"],
                "event_viewer": ["xterm -e 'journalctl -xe; bash'"],
            }
            candidates = mapping.get(name, [])
            for c in candidates:
                try:
                    subprocess.Popen(c, shell=True)
                    return True, f"Opened via: {c}"
                except Exception:
                    continue
            return False, "No suitable native tool found on this Linux system"
        else:
            return False, "Native tool opening not supported on this OS"
    except Exception as e:
        return False, f"Error: {e}"
