"""Fixed root operations. Parameters arrive on stdin, never as shell text."""

import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import subprocess
import sys
import time


def command(args, timeout=120, input=None, check=True):
    result = subprocess.run(
        args,
        input=input,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if check and result.returncode:
        raise RuntimeError("System operation failed: " + result.stdout[-4096:])
    return {"exit_code": result.returncode, "output": result.stdout[:524288]}


def main(v):
    action, p, root = v["action"], v["params"], Path(v["root"])
    now = datetime.datetime.now(datetime.timezone.utc)
    if action == "prerequisites.install":
        command(["/usr/bin/apt-get", "update"], timeout=240)
        result = command(
            [
                "/usr/bin/apt-get",
                "-y",
                "install",
                "python3",
                "nftables",
                "wireshark-common",
            ],
            timeout=840,
        )
        result["capture_driver"] = (
            "Linux dumpcap; Wxlfgar service permissions must be set by its installer"
        )
        return result
    if action == "services.list":
        return command(
            [
                "/usr/bin/systemctl",
                "list-units",
                "--type=service",
                "--all",
                "--no-pager",
                "--plain",
            ]
        )
    if action == "service.control":
        return command(["/usr/bin/systemctl", p["operation"], p["name"]], timeout=60)
    if action == "processes.list":
        records=[]
        for directory in Path('/proc').iterdir():
            if not directory.name.isdigit():continue
            try:
                raw=(directory/'stat').read_text();fields=raw[raw.rfind(') ')+2:].split()
                uid=directory.stat().st_uid
                try:owner=pwd.getpwuid(uid).pw_name
                except KeyError:owner=str(uid)
                records.append({'pid':int(directory.name),'name':(directory/'comm').read_text().strip(),'owner':owner,'start_token':fields[19]})
            except (OSError,IndexError):continue
            if len(records)>=2000:break
        return {'processes':records,'truncated':len(records)>=2000}
    if action == "process.stop":
        pid = p["pid"]
        if pid in [os.getpid(), os.getppid(), 1]:
            raise ValueError("Protected process")
        name = Path(f"/proc/{pid}/comm").read_text().strip()
        if name.startswith("northgate") or name in ["systemd", "sshd"]:
            raise ValueError("Protected management process")
        fd = os.pidfd_open(pid)
        try:
            raw=Path(f'/proc/{pid}/stat').read_text();fields=raw[raw.rfind(') ')+2:].split()
            if fields[19]!=p['start_token']:raise ValueError('Process changed; refresh inventory before terminating')
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)
        return {"pid": pid, "signal": "SIGTERM", "termination_requested": True}
    if action == "logs.read":
        args = [
            "/usr/bin/journalctl",
            "--since",
            f"{p['since']} minutes ago",
            "-n",
            str(p["limit"]),
            "--no-pager",
            "-o",
            "json",
        ]
        if p["channel"] == "auth":
            args += ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"]
        elif p["channel"] != "journal":
            raise ValueError("Choose journal or auth on Linux")
        return command(args, timeout=30)
    if action in ["reboot.status", "posture"]:
        result = {
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "pending_reboot": Path("/var/run/reboot-required").exists(),
            "users": command(["/usr/bin/who"], check=False),
            "sudo_members": command(["/usr/bin/getent", "group", "sudo"], check=False),
            "tpm_present": Path("/sys/class/tpm/tpm0").exists(),
        }
        if action == "posture":
            result["encryption"] = command(
                ["/usr/bin/lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"],
                check=False,
            )
            result["firewall"] = (
                command(["/usr/sbin/nft", "-j", "list", "ruleset"], check=False)
                if shutil.which("nft")
                else {"available": False}
            )
            result["security_services"] = command(
                [
                    "/usr/bin/systemctl",
                    "is-active",
                    "auditd",
                    "wazuh-agent",
                    "clamav-daemon",
                ],
                check=False,
            )
            result["secure_boot"] = (
                command(["/usr/bin/mokutil", "--sb-state"], check=False)
                if shutil.which("mokutil")
                else {"available": False}
            )
        return result
    if action == "reboot":
        command(
            [
                "/usr/bin/systemd-run",
                "--unit=northgate-rmm-reboot-" + v["job"],
                "--on-active=" + str(p["delay"]) + "s",
                "--timer-property=AccuracySec=1s",
                "/usr/bin/systemctl",
                "reboot",
            ]
        )
        return {
            "reboot_scheduled": True,
            "delay_seconds": p["delay"],
            "previous_boot_id": Path("/proc/sys/kernel/random/boot_id")
            .read_text()
            .strip(),
        }
    if action == "packages.list":
        return command(
            ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"]
        )
    if action in [
        "package.install",
        "package.remove",
        "patches.scan",
        "patches.install",
    ]:
        os.environ["DEBIAN_FRONTEND"] = "noninteractive"
        if action == "patches.scan":
            command(["/usr/bin/apt-get", "update"], timeout=240)
            return command(["/usr/bin/apt-get", "-s", "upgrade"], timeout=90)
        args = ["/usr/bin/apt-get", "-y", "-o", "Dpkg::Options::=--force-confold"]
        if action == "patches.install":
            args += ["upgrade"]
        else:
            args += [
                "install" if action == "package.install" else "remove",
                "--",
                p["name"],
            ]
        result = command(args, timeout=840)
        result["pending_reboot"] = Path("/var/run/reboot-required").exists()
        return result
    if action == "encryption.status":
        return {
            "volumes": command(
                ["/usr/bin/lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"]
            ),
            "recovery_keys": "Existing LUKS passphrases are not extractable; provision a managed recovery key separately.",
        }
    if action == "recovery.rotate":
        name = "ng-rmm-recovery"
        stamp = root / "recovery-account.json"
        try:
            pwd.getpwnam(name)
            exists = True
        except KeyError:
            exists = False
        if exists and not stamp.exists():
            raise ValueError("Existing account is not managed by this worker")
        if not exists:
            command(
                ["/usr/sbin/useradd", "--create-home", "--shell", "/bin/bash", name]
            )
        command(["/usr/sbin/usermod", "-aG", "sudo", name])
        password = secrets.token_urlsafe(32)
        command(["/usr/sbin/chpasswd"], input=name + ":" + password + "\n")
        expires = now + datetime.timedelta(hours=p["hours"])
        command(
            [
                "/usr/bin/chage",
                "-E",
                (expires + datetime.timedelta(days=1)).date().isoformat(),
                name,
            ]
        )
        unit = "northgate-rmm-recovery-expiry"
        command(["/usr/bin/systemctl", "stop", unit + ".timer"], check=False)
        command(["/usr/bin/systemctl", "reset-failed", unit + ".service"], check=False)
        unit_root = Path("/etc/systemd/system")
        (unit_root / (unit + ".service")).write_text(
            "[Unit]\nDescription=Expire NorthGate recovery account\n[Service]\nType=oneshot\nExecStart=/usr/sbin/usermod --lock ng-rmm-recovery\n"
        )
        (unit_root / (unit + ".timer")).write_text(
            "[Unit]\nDescription=NorthGate recovery account expiry\n[Timer]\nOnCalendar="
            + expires.strftime("%Y-%m-%d %H:%M:%S UTC")
            + "\nAccuracySec=1s\nPersistent=true\n[Install]\nWantedBy=timers.target\n"
        )
        for suffix in [".service", ".timer"]:
            (unit_root / (unit + suffix)).chmod(0o644)
        command(["/usr/bin/systemctl", "daemon-reload"])
        command(["/usr/bin/systemctl", "enable", "--now", unit + ".timer"])
        stamp.write_text(json.dumps({"name": name, "expires": expires.isoformat()}))
        stamp.chmod(0o600)
        return {
            "username": name,
            "password": password,
            "expires": expires.isoformat(),
            "rotation": v["job"],
        }
    if action == "isolation.release":
        if not (root / "isolation.json").exists():
            return {"isolated": False}
        result = command(
            ["/usr/sbin/nft", "delete", "table", "inet", "northgate_rmm_ops"],
            check=False,
        )
        if (
            result["exit_code"]
            and command(
                ["/usr/sbin/nft", "list", "table", "inet", "northgate_rmm_ops"],
                check=False,
            )["exit_code"]
            == 0
        ):
            raise RuntimeError("Isolation cleanup failed")
        (root / "isolation.json").unlink(missing_ok=True)
        return {"isolated": False}
    if action == "isolation.start":
        ip = str(ipaddress.IPv4Address(v["server_ip"]))
        stamp = root / "isolation.json"
        if stamp.exists():
            raise ValueError("Isolation already active; release before renewing")
        if (
            command(
                ["/usr/sbin/nft", "list", "table", "inet", "northgate_rmm_ops"],
                check=False,
            )["exit_code"]
            == 0
        ):
            raise ValueError("Unreconciled isolation table")
        # Independent expiry exists before any packet-filter change.
        command(
            [
                "/usr/bin/systemd-run",
                "--unit=northgate-rmm-isolation-" + v["job"],
                "--on-active=" + str(p["seconds"]) + "s",
                "--timer-property=AccuracySec=1s",
                v["binary"],
                "--release-isolation",
                v["config"],
            ]
        )
        stamp.write_text(
            json.dumps({"expires": time.time() + p["seconds"], "management_ip": ip})
        )
        stamp.chmod(0o600)
        rules = (
            "table inet northgate_rmm_ops {\n"
            "chain outbound { type filter hook output priority -200; policy drop; "
            f'oifname "lo" accept; ip daddr {ip} accept; }}\n'
            "chain inbound { type filter hook input priority -200; policy drop; "
            f'iifname "lo" accept; ip saddr {ip} accept; }}\n}}\n'
        )
        try:
            command(["/usr/sbin/nft", "-f", "-"], input=rules)
        except BaseException:
            command(
                ["/usr/sbin/nft", "delete", "table", "inet", "northgate_rmm_ops"],
                check=False,
            )
            stamp.unlink(missing_ok=True)
            raise
        return {
            "isolated": True,
            "expires_in_seconds": p["seconds"],
            "management_ip": ip,
        }
    raise ValueError("Unsupported Linux operation")


try:
    value = json.load(sys.stdin)
    print(json.dumps(main(value), ensure_ascii=True))
except Exception as error:
    print(json.dumps({"error": str(error)[:4096]}))
    sys.exit(1)
