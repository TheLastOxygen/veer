# SPDX-License-Identifier: MIT
"""Windows Firewall rules for Veer: inbound, Private profile only, from the
local subnet only. Adding and removing them needs an elevated prompt;
without one, the commands are printed for the user to run."""
import ctypes
import json
import subprocess
import sys

from . import APP_NAME, mdns

RULE_PREFIX = f'{APP_NAME} - '
TCP_RULE = RULE_PREFIX + 'AirDrop HTTPS (TCP-In)'
MDNS_RULE = RULE_PREFIX + 'mDNS (UDP-In)'


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def rules(port):
    """(name, protocol, local port) of each rule Veer needs."""
    return [(TCP_RULE, 'TCP', str(port)), (MDNS_RULE, 'UDP', str(mdns.PORT))]


def add_commands(port):
    return [['netsh', 'advfirewall', 'firewall', 'add', 'rule', f'name={name}', 'dir=in',
             'action=allow', f'protocol={protocol}', f'localport={local}', 'profile=private',
             'remoteip=localsubnet', 'edge=no',
             f'description=Lets Macs on the local network reach {APP_NAME}.']
            for name, protocol, local in rules(port)]


def remove_commands(names=(TCP_RULE, MDNS_RULE)):
    return [['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={name}']
            for name in names]


def quoted(command):
    return subprocess.list2cmdline(command)


def run(commands, dry_run=False, out=None):
    """Run the commands if elevated, else print them. Returns an exit code."""
    out = out or sys.stdout
    if dry_run or not is_admin():
        if not dry_run:
            print('Changing firewall rules needs an elevated prompt. Run these in a terminal '
                  'opened with "Run as administrator", or rerun this command there:', file=out)
        for command in commands:
            print('  ' + quoted(command), file=out)
        return 0 if dry_run else 1
    status = 0
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True)
        print(f'{quoted(command)}\n  -> {(result.stdout or result.stderr).strip()}', file=out)
        status = status or result.returncode
    return status


def _powershell_json(script):
    result = subprocess.run(
        ['powershell', '-NoProfile', '-NonInteractive', '-Command',
         f'{script} | ConvertTo-Json -Depth 3'],
        capture_output=True, text=True, timeout=60)
    if result.returncode != 0 or not result.stdout.strip():
        return []
    value = json.loads(result.stdout)
    return value if isinstance(value, list) else [value]


def veer_rules():
    return _powershell_json(
        f"Get-NetFirewallRule -DisplayName '{RULE_PREFIX}*' -ErrorAction SilentlyContinue | "
        "Select-Object DisplayName,Enabled,@{n='Profile';e={$_.Profile.ToString()}},"
        "@{n='Action';e={$_.Action.ToString()}}")


def python_block_rules(program=sys.executable):
    """Inbound rules that block this Python. Windows creates them when its
    "allow this app" dialog is cancelled, and a block beats any allow."""
    escaped = program.replace("'", "''")
    return _powershell_json(
        f"Get-NetFirewallApplicationFilter -Program '{escaped}' -ErrorAction SilentlyContinue | "
        "Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Inbound' -and "
        "$_.Action -eq 'Block' -and $_.Enabled -eq 'True' } | "
        "Select-Object DisplayName,@{n='Profile';e={$_.Profile.ToString()}}")


def network_profiles():
    return _powershell_json(
        "Get-NetConnectionProfile | Select-Object InterfaceAlias,Name,"
        "@{n='Category';e={$_.NetworkCategory.ToString()}}")


def show(out=None):
    out = out or sys.stdout
    if sys.platform != 'win32':
        print('Firewall rules are only managed on Windows.', file=out)
        return 0
    print('Networks (Veer\'s rules apply to Private ones only):', file=out)
    for profile in network_profiles():
        warning = '' if profile.get('Category') in ('Private', 'DomainAuthenticated') else \
            '   <- Public: Macs cannot reach Veer here; set this network to Private'
        print(f"  {profile.get('InterfaceAlias')}: {profile.get('Name')} "
              f"[{profile.get('Category')}]{warning}", file=out)
    found = veer_rules()
    print('Veer rules:', file=out)
    for rule in found:
        print(f"  {rule.get('DisplayName')}: {rule.get('Action')}, profile {rule.get('Profile')}, "
              f"enabled {rule.get('Enabled')}", file=out)
    if not found:
        print('  none; add them with "veer firewall add" from an elevated prompt', file=out)
    blocks = python_block_rules()
    if blocks:
        print(f'Rules blocking {sys.executable} (they override Veer\'s; remove them in '
              '"Windows Defender Firewall with Advanced Security" > Inbound Rules):', file=out)
        for rule in blocks:
            print(f"  {rule.get('DisplayName')}: profile {rule.get('Profile')}", file=out)
    return 0
