"""
Reference implementation of the KDNet / BCD / WinDbg helpers used by
Minifilter_Automation PowerShell scripts.

This module is the mock-testable core. The production scripts live under
scripts/ and target a Windows host + TARGET pair. The functions here
mirror those scripts so every branch can be exercised on Linux CI.
"""

from __future__ import annotations

import json
import re
from typing import Dict, Optional, Tuple


DEFAULT_PORT = "50008"
DEFAULT_KEY = "1.2.3.4"
DEFAULT_DRIVER_NAME = "InspectorDrv"
DEFAULT_SYMBOL_MODULE = "inspector_driver"
DEFAULT_WORKSPACE = r"C:\Development\Damian\Drivers\WinDbgWorkspace.xml"

REMOVED_BREAKPOINTS = (
    "DispatchDeviceControl",
    "EnumerateProcesses",
)

IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
)
PORT_RE = re.compile(r"^\d+$")


class KdnetConfigError(ValueError):
    """Raised when a caller passes an invalid KDNET setting."""


def is_valid_ipv4(value: Optional[str]) -> bool:
    if not value or not isinstance(value, str):
        return False
    return bool(IPV4_RE.match(value.strip()))


def is_valid_port(value: object) -> bool:
    text = str(value).strip() if value is not None else ""
    if not PORT_RE.match(text):
        return False
    n = int(text)
    return 1 <= n <= 65535


def is_valid_key(value: Optional[str]) -> bool:
    if not value or not isinstance(value, str):
        return False
    text = value.strip()
    if len(text) < 3:
        return False
    if any(ch.isspace() for ch in text):
        return False
    return True


def is_valid_driver_name(value: Optional[str]) -> bool:
    if not value or not isinstance(value, str):
        return False
    text = value.strip()
    if not text:
        return False
    # Service names cannot contain path separators or spaces.
    if any(ch in text for ch in "\\/:*?\"<>| "):
        return False
    return True


def validate_kdnet_params(
    port: object = DEFAULT_PORT,
    key: str = DEFAULT_KEY,
    driver_name: str = DEFAULT_DRIVER_NAME,
    host_ip: Optional[str] = None,
    require_host_ip: bool = False,
) -> Dict[str, str]:
    if not is_valid_port(port):
        raise KdnetConfigError(f"Port must be an integer in 1..65535. Got: {port!r}")
    if not is_valid_key(key):
        raise KdnetConfigError(f"Key is invalid: {key!r}")
    if not is_valid_driver_name(driver_name):
        raise KdnetConfigError(f"DriverName is invalid: {driver_name!r}")
    if require_host_ip and not is_valid_ipv4(host_ip):
        raise KdnetConfigError(
            f"HostIp is required and must be dotted IPv4. Got: {host_ip!r}"
        )
    result = {
        "port": str(port).strip(),
        "key": key.strip(),
        "driver_name": driver_name.strip(),
    }
    if host_ip:
        result["host_ip"] = host_ip.strip()
    return result


def parse_bcdedit_key_values(text: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not text:
        return mapping
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lowered = line.lower()
        if (
            lowered.startswith("the boot configuration")
            or lowered.startswith("an error has occurred")
            or lowered.startswith("access is denied")
        ):
            continue
        match = re.match(r"^(\S+)\s+(\S.*)$", line)
        if match:
            mapping[match.group(1).lower()] = match.group(2).strip()
    return mapping


def parse_kdnet_settings(dbgsettings_text: str, enum_text: str = "") -> Dict[str, Optional[str]]:
    dbg = parse_bcdedit_key_values(dbgsettings_text)
    enum = parse_bcdedit_key_values(enum_text)
    combined = f"{dbgsettings_text or ''}\n{enum_text or ''}"
    access_denied = "access is denied" in combined.lower()
    return {
        "debugtype": dbg.get("debugtype"),
        "hostip": dbg.get("hostip"),
        "port": dbg.get("port"),
        "key": dbg.get("key"),
        "testsigning": enum.get("testsigning"),
        "debug": enum.get("debug"),
        "nointegritychecks": enum.get("nointegritychecks"),
        "access_denied": access_denied,  # type: ignore[dict-item]
    }


def build_kdnet_listen_string(port: object = DEFAULT_PORT, key: str = DEFAULT_KEY) -> str:
    params = validate_kdnet_params(port=port, key=key)
    return f"net:port={params['port']},key={params['key']}"


def build_bcdedit_dbgsettings_args(
    host_ip: str,
    port: object = DEFAULT_PORT,
    key: str = DEFAULT_KEY,
) -> Tuple[str, ...]:
    params = validate_kdnet_params(port=port, key=key, host_ip=host_ip, require_host_ip=True)
    return (
        "/dbgsettings",
        "net",
        f"hostip:{params['host_ip']}",
        f"port:{params['port']}",
        f"key:{params['key']}",
    )


def derive_symbol_module(sys_module_name: str, override: str = "") -> str:
    if override and override.strip():
        return override.strip()
    name = sys_module_name.strip()
    if name.lower().endswith(".sys"):
        name = name[:-4]
    if not name:
        return DEFAULT_SYMBOL_MODULE
    return name


def generate_wds(
    project_root: str,
    build_config: str,
    sys_module_name: str,
    symbol_module: str = "",
) -> str:
    module = derive_symbol_module(sys_module_name, symbol_module)
    return (
        "!sym noisy\n"
        f".sympath {project_root}\\x64\\{build_config};"
        "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols\n"
        f".reload /f /i {sys_module_name}\n"
        "\n"
        ".echo [READY] Symbol path and reload complete.\n"
        "\n"
        f'bp {module}!DriverEntry "echo [BP] === DriverEntry ===; kv"\n'
        "bl\n"
        "\n"
        ".echo [READY] Breakpoint is set on DriverEntry. Load or reload the driver to hit it.\n"
    )


def wds_has_forbidden_breakpoints(wds_text: str) -> Tuple[bool, Tuple[str, ...]]:
    found = tuple(name for name in REMOVED_BREAKPOINTS if name in wds_text)
    return (len(found) > 0, found)


def wds_has_driver_entry_breakpoint(wds_text: str) -> bool:
    return bool(re.search(r"\bbp\s+\S+!DriverEntry\b", wds_text))


def build_windbg_command_line(
    port: object = DEFAULT_PORT,
    key: str = DEFAULT_KEY,
    symbol_path: str = r"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",
) -> Tuple[str, ...]:
    listen = build_kdnet_listen_string(port, key)
    return ("-k", listen, "-y", symbol_path)


def build_target_sidecar(
    driver_name: str,
    host_ip: str,
    port: object,
    key: str,
    generated_utc: str = "2026-09-30T00:00:00+00:00",
) -> str:
    params = validate_kdnet_params(
        port=port,
        key=key,
        driver_name=driver_name,
        host_ip=host_ip,
        require_host_ip=True,
    )
    payload = {
        "generatedUtc": generated_utc,
        "driverName": params["driver_name"],
        "hostIp": params["host_ip"],
        "port": params["port"],
        "key": params["key"],
    }
    return json.dumps(payload, indent=2)


def parse_listen_string(text: str) -> Dict[str, str]:
    """Parse 'net:port=50008,key=1.2.3.4' (with optional surrounding quotes)."""
    if not text:
        raise KdnetConfigError("listen string is empty")
    cleaned = text.strip().strip('"').strip("'")
    if not cleaned.lower().startswith("net:"):
        raise KdnetConfigError(f"listen string must start with net: Got: {text!r}")
    body = cleaned[4:]
    parts = {}
    for item in body.split(","):
        if "=" not in item:
            continue
        k, v = item.split("=", 1)
        parts[k.strip().lower()] = v.strip()
    if "port" not in parts or "key" not in parts:
        raise KdnetConfigError(f"listen string missing port or key: {text!r}")
    validate_kdnet_params(port=parts["port"], key=parts["key"])
    return parts


def extract_ps_default(script_text: str, param_name: str) -> Optional[str]:
    """
    Pull a simple default from a PowerShell param block:
        [string]$Port = "50008",
    """
    pattern = rf'\$({re.escape(param_name)})\s*=\s*"([^"]*)"'
    match = re.search(pattern, script_text)
    if not match:
        return None
    return match.group(2)
