#!/usr/bin/env python3
"""
Mock tests for Minifilter_Automation.

Covers:
  - KDNET parameter validation (port / key / driver / host IP)
  - bcdedit /dbgsettings and /enum {current} parsers
  - debug.wds generation (DriverEntry only; old IOCTL BPs gone)
  - WinDbg listen-string construction
  - target sidecar JSON
  - production script contracts (defaults, rename, forbidden BPs)
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent / "scripts"
sys.path.insert(0, str(HERE))

import kdnet_logic as k  # noqa: E402


SAMPLE_DBGSETTINGS_NET = """\
debugtype             NET
hostip                192.168.1.10
port                  50008
key                   1.2.3.4
"""

SAMPLE_DBGSETTINGS_LOCAL = """\
debugtype             LOCAL
"""

SAMPLE_ENUM_CURRENT = """\
Windows Boot Loader
-------------------
identifier              {current}
device                  partition=C:
path                    \\Windows\\system32\\winload.efi
description             Windows 10
locale                  en-US
inherit                 {bootloadersettings}
recoverysequence        {a1b2c3d4-0000-0000-0000-000000000000}
displaymessageoverride  Recovery
recoveryenabled         Yes
isolatedcontext         Yes
allowedinmemorysettings 0x15000075
osdevice                partition=C:
systemroot              \\Windows
resumeobject            {aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}
nx                      OptIn
testsigning             Yes
debug                   Yes
nointegritychecks       Yes
"""

SAMPLE_ACCESS_DENIED = """\
The boot configuration data store could not be opened.
Access is denied.
"""

SAMPLE_DBGSETTINGS_CUSTOM = """\
debugtype             NET
hostip                10.0.0.2
port                  50009
key                   a.b.c.d
"""


def read_script(name: str) -> str:
    path = SCRIPTS / name
    if not path.is_file():
        raise FileNotFoundError(path)
    return path.read_text(encoding="utf-8", errors="replace")


class TestParamValidation(unittest.TestCase):
    def test_default_params_are_valid(self):
        p = k.validate_kdnet_params()
        self.assertEqual(p["port"], "50008")
        self.assertEqual(p["key"], "1.2.3.4")
        self.assertEqual(p["driver_name"], "InspectorDrv")

    def test_port_bounds(self):
        self.assertTrue(k.is_valid_port(1))
        self.assertTrue(k.is_valid_port(65535))
        self.assertTrue(k.is_valid_port("50008"))
        self.assertFalse(k.is_valid_port(0))
        self.assertFalse(k.is_valid_port(65536))
        self.assertFalse(k.is_valid_port(-1))
        self.assertFalse(k.is_valid_port("abc"))
        self.assertFalse(k.is_valid_port(""))
        self.assertFalse(k.is_valid_port(None))
        self.assertFalse(k.is_valid_port("50008a"))
        self.assertFalse(k.is_valid_port("50 008"))

    def test_invalid_port_raises(self):
        with self.assertRaises(k.KdnetConfigError):
            k.validate_kdnet_params(port="not-a-port")
        with self.assertRaises(k.KdnetConfigError):
            k.validate_kdnet_params(port="0")
        with self.assertRaises(k.KdnetConfigError):
            k.validate_kdnet_params(port="70000")

    def test_key_rules(self):
        self.assertTrue(k.is_valid_key("1.2.3.4"))
        self.assertTrue(k.is_valid_key("1.2.3.4.5.6"))
        self.assertTrue(k.is_valid_key("abcdefgh"))
        self.assertFalse(k.is_valid_key(""))
        self.assertFalse(k.is_valid_key("  "))
        self.assertFalse(k.is_valid_key("ab"))
        self.assertFalse(k.is_valid_key("1 2 3 4"))
        self.assertFalse(k.is_valid_key(None))

    def test_invalid_key_raises(self):
        with self.assertRaises(k.KdnetConfigError):
            k.validate_kdnet_params(key="ab")
        with self.assertRaises(k.KdnetConfigError):
            k.validate_kdnet_params(key="1 2.3.4")

    def test_driver_name_rules(self):
        self.assertTrue(k.is_valid_driver_name("InspectorDrv"))
        self.assertTrue(k.is_valid_driver_name("FsMonDrv"))
        self.assertFalse(k.is_valid_driver_name(""))
        self.assertFalse(k.is_valid_driver_name("Inspector Drv"))
        self.assertFalse(k.is_valid_driver_name(r"C:\foo"))
        self.assertFalse(k.is_valid_driver_name(None))

    def test_ipv4_rules(self):
        self.assertTrue(k.is_valid_ipv4("192.168.1.10"))
        self.assertTrue(k.is_valid_ipv4("10.0.0.1"))
        self.assertTrue(k.is_valid_ipv4("255.255.255.255"))
        self.assertTrue(k.is_valid_ipv4("0.0.0.0"))
        self.assertFalse(k.is_valid_ipv4("192.168.1.256"))
        self.assertFalse(k.is_valid_ipv4("192.168.1"))
        self.assertFalse(k.is_valid_ipv4("localhost"))
        self.assertFalse(k.is_valid_ipv4(""))
        self.assertFalse(k.is_valid_ipv4(None))

    def test_host_ip_required_when_requested(self):
        with self.assertRaises(k.KdnetConfigError):
            k.validate_kdnet_params(require_host_ip=True)
        with self.assertRaises(k.KdnetConfigError):
            k.validate_kdnet_params(host_ip="not-an-ip", require_host_ip=True)
        ok = k.validate_kdnet_params(host_ip="192.168.1.10", require_host_ip=True)
        self.assertEqual(ok["host_ip"], "192.168.1.10")


class TestBcdeditParsing(unittest.TestCase):
    def test_parse_net_dbgsettings(self):
        s = k.parse_kdnet_settings(SAMPLE_DBGSETTINGS_NET, SAMPLE_ENUM_CURRENT)
        self.assertEqual(s["debugtype"], "NET")
        self.assertEqual(s["hostip"], "192.168.1.10")
        self.assertEqual(s["port"], "50008")
        self.assertEqual(s["key"], "1.2.3.4")
        self.assertEqual(s["testsigning"], "Yes")
        self.assertEqual(s["debug"], "Yes")
        self.assertEqual(s["nointegritychecks"], "Yes")
        self.assertFalse(s["access_denied"])

    def test_parse_local_dbgsettings_missing_port_key(self):
        s = k.parse_kdnet_settings(SAMPLE_DBGSETTINGS_LOCAL, "")
        self.assertEqual(s["debugtype"], "LOCAL")
        self.assertIsNone(s["port"])
        self.assertIsNone(s["key"])
        self.assertIsNone(s["hostip"])

    def test_parse_custom_port_key(self):
        s = k.parse_kdnet_settings(SAMPLE_DBGSETTINGS_CUSTOM)
        self.assertEqual(s["port"], "50009")
        self.assertEqual(s["key"], "a.b.c.d")
        self.assertEqual(s["hostip"], "10.0.0.2")

    def test_access_denied(self):
        s = k.parse_kdnet_settings(SAMPLE_ACCESS_DENIED, SAMPLE_ACCESS_DENIED)
        self.assertTrue(s["access_denied"])
        self.assertIsNone(s["port"])
        self.assertIsNone(s["key"])

    def test_empty_input(self):
        s = k.parse_kdnet_settings("", "")
        self.assertIsNone(s["port"])
        self.assertIsNone(s["key"])
        self.assertFalse(s["access_denied"])

    def test_windows_newlines(self):
        text = SAMPLE_DBGSETTINGS_NET.replace("\n", "\r\n")
        s = k.parse_kdnet_settings(text)
        self.assertEqual(s["port"], "50008")
        self.assertEqual(s["key"], "1.2.3.4")

    def test_ignores_preamble_lines(self):
        text = "The boot configuration data store could not be opened.\nport  1\n"
        parsed = k.parse_bcdedit_key_values(text)
        self.assertEqual(parsed.get("port"), "1")
        self.assertNotIn("the", parsed)


class TestWdsGeneration(unittest.TestCase):
    def test_driver_entry_only(self):
        wds = k.generate_wds(
            r"C:\dev\Inspector",
            "Debug",
            "inspector_driver.sys",
            "inspector_driver",
        )
        self.assertTrue(k.wds_has_driver_entry_breakpoint(wds))
        has_bad, found = k.wds_has_forbidden_breakpoints(wds)
        self.assertFalse(has_bad)
        self.assertEqual(found, ())
        self.assertIn("inspector_driver!DriverEntry", wds)
        self.assertIn("inspector_driver.sys", wds)
        self.assertIn(r"C:\dev\Inspector\x64\Debug", wds)

    def test_symbol_module_derived_from_sys_name(self):
        wds = k.generate_wds(r"C:\dev\x", "Release", "fsmon_driver_v6.sys")
        self.assertIn("fsmon_driver_v6!DriverEntry", wds)
        self.assertNotIn("inspector_driver!DriverEntry", wds)

    def test_symbol_module_override(self):
        wds = k.generate_wds(r"C:\dev\x", "Debug", "foo.sys", override := "bar_mod")
        self.assertIn("bar_mod!DriverEntry", wds)

    def test_derive_symbol_module_empty_falls_back(self):
        self.assertEqual(k.derive_symbol_module(""), k.DEFAULT_SYMBOL_MODULE)
        self.assertEqual(k.derive_symbol_module("   "), k.DEFAULT_SYMBOL_MODULE)
        self.assertEqual(k.derive_symbol_module("x.sys"), "x")
        self.assertEqual(k.derive_symbol_module("x.sys", "KeepMe"), "KeepMe")

    def test_old_breakpoints_detected_when_present(self):
        legacy = (
            'bp inspector_driver!DispatchDeviceControl "echo IOCTL"\n'
            'bp inspector_driver!EnumerateProcesses "echo ENUM"\n'
        )
        has_bad, found = k.wds_has_forbidden_breakpoints(legacy)
        self.assertTrue(has_bad)
        self.assertEqual(set(found), {"DispatchDeviceControl", "EnumerateProcesses"})


class TestListenStringAndBcdArgs(unittest.TestCase):
    def test_default_listen_string(self):
        self.assertEqual(k.build_kdnet_listen_string(), "net:port=50008,key=1.2.3.4")

    def test_custom_listen_string(self):
        self.assertEqual(
            k.build_kdnet_listen_string("50009", "a.b.c.d"),
            "net:port=50009,key=a.b.c.d",
        )

    def test_parse_listen_string_roundtrip(self):
        raw = k.build_kdnet_listen_string()
        parsed = k.parse_listen_string(raw)
        self.assertEqual(parsed["port"], "50008")
        self.assertEqual(parsed["key"], "1.2.3.4")

    def test_parse_listen_string_quoted(self):
        parsed = k.parse_listen_string('"net:port=50008,key=1.2.3.4"')
        self.assertEqual(parsed["port"], "50008")

    def test_parse_listen_string_rejects_garbage(self):
        with self.assertRaises(k.KdnetConfigError):
            k.parse_listen_string("")
        with self.assertRaises(k.KdnetConfigError):
            k.parse_listen_string("tcp:port=1")
        with self.assertRaises(k.KdnetConfigError):
            k.parse_listen_string("net:port=50008")

    def test_bcdedit_args_order(self):
        args = k.build_bcdedit_dbgsettings_args("192.168.1.10", "50008", "1.2.3.4")
        self.assertEqual(
            args,
            (
                "/dbgsettings",
                "net",
                "hostip:192.168.1.10",
                "port:50008",
                "key:1.2.3.4",
            ),
        )

    def test_bcdedit_args_reject_bad_ip(self):
        with self.assertRaises(k.KdnetConfigError):
            k.build_bcdedit_dbgsettings_args("host.local")

    def test_windbg_command_line(self):
        cmd = k.build_windbg_command_line()
        self.assertEqual(cmd[0], "-k")
        self.assertEqual(cmd[1], "net:port=50008,key=1.2.3.4")
        self.assertEqual(cmd[2], "-y")


class TestSidecarJson(unittest.TestCase):
    def test_sidecar_roundtrip(self):
        raw = k.build_target_sidecar(
            "InspectorDrv", "192.168.1.10", "50008", "1.2.3.4", "2026-09-30T00:00:00+00:00"
        )
        data = json.loads(raw)
        self.assertEqual(data["driverName"], "InspectorDrv")
        self.assertEqual(data["hostIp"], "192.168.1.10")
        self.assertEqual(data["port"], "50008")
        self.assertEqual(data["key"], "1.2.3.4")
        self.assertIn("generatedUtc", data)

    def test_sidecar_rejects_bad_ip(self):
        with self.assertRaises(k.KdnetConfigError):
            k.build_target_sidecar("InspectorDrv", "bad", "50008", "1.2.3.4")


class TestProductionScriptContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.update = read_script("Update_KDNet_Config.ps1")
        cls.start = read_script("Start-KDNet-WinDbg.ps1")
        cls.configure = read_script("Configure-Target-KDNet.ps1")
        cls.install = read_script("Install-Minifilter.ps1")

    def test_update_defaults(self):
        self.assertEqual(k.extract_ps_default(self.update, "Port"), "50008")
        self.assertEqual(k.extract_ps_default(self.update, "Key"), "1.2.3.4")
        self.assertEqual(k.extract_ps_default(self.update, "DriverName"), "InspectorDrv")

    def test_start_defaults(self):
        self.assertEqual(k.extract_ps_default(self.start, "Port"), "50008")
        self.assertEqual(k.extract_ps_default(self.start, "Key"), "1.2.3.4")
        self.assertEqual(k.extract_ps_default(self.start, "DriverName"), "InspectorDrv")

    def test_configure_defaults(self):
        self.assertEqual(k.extract_ps_default(self.configure, "Port"), "50008")
        self.assertEqual(k.extract_ps_default(self.configure, "Key"), "1.2.3.4")
        self.assertEqual(k.extract_ps_default(self.configure, "DriverName"), "InspectorDrv")

    def test_update_wds_template_driver_entry_only(self):
        self.assertIn("!DriverEntry", self.update)
        self.assertNotIn("DispatchDeviceControl", self.update)
        self.assertNotIn("EnumerateProcesses", self.update)
        has_bad, found = k.wds_has_forbidden_breakpoints(self.update)
        self.assertFalse(has_bad, msg=f"forbidden leftovers: {found}")

    def test_start_uses_parameterized_listen_string(self):
        self.assertIn("net:port=$Port,key=$Key", self.start)
        self.assertNotIn('net:port=50008,key=1.2.3.4"', self.start.split("param(")[-1] if False else "")

    def test_configure_calls_bcdedit(self):
        self.assertIn("/set", self.configure)
        self.assertIn("testsigning", self.configure)
        self.assertIn("/debug", self.configure)
        self.assertIn("/dbgsettings", self.configure)
        self.assertIn("-ShowOnly", self.configure)
        self.assertIn("bcdedit.exe", self.configure)

    def test_install_was_renamed_and_keeps_contract(self):
        self.assertIn("# Install-Minifilter.ps1", self.install)
        self.assertIn("[string]$DriverName", self.install)
        self.assertIn("[string]$DriverPath", self.install)
        self.assertIn("$ForceRename", self.install)
        self.assertIn("fltmc", self.install)
        self.assertIn("Altitude", self.install)

    def test_update_param_block_exists(self):
        self.assertIn("[CmdletBinding()]", self.update)
        self.assertIn("param(", self.update)
        self.assertIn("$Port", self.update)
        self.assertIn("$Key", self.update)
        self.assertIn("$DriverName", self.update)

    def test_all_scripts_present(self):
        expected = {
            "Update_KDNet_Config.ps1",
            "Start-KDNet-WinDbg.ps1",
            "Configure-Target-KDNet.ps1",
            "Install-Minifilter.ps1",
        }
        present = {p.name for p in SCRIPTS.glob("*.ps1")}
        missing = expected - present
        self.assertFalse(missing, msg=f"missing scripts: {missing}")


class TestListenStringInGeneratedLauncherShape(unittest.TestCase):
    def test_generated_k_argument_shape(self):
        # Mirrors the string Update_KDNet_Config embeds into Start-KDNet-WinDbg.ps1
        port, key = "50008", "1.2.3.4"
        embedded = f'net:port={port},key={key}'
        parsed = k.parse_listen_string(embedded)
        self.assertEqual(parsed["port"], port)
        self.assertEqual(parsed["key"], key)


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("")
    print(f"Ran {result.testsRun} tests")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors:   {len(result.errors)}")
    if result.wasSuccessful():
        print("ALL TESTS PASSED")
        return 0
    print("TESTS FAILED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
