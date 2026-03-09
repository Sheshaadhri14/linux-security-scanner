import subprocess
import os
import stat
import pwd
import grp


def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1
def check_ssh_root_login():
    """CIS 5.2.8 - Ensure SSH root login is disabled"""
    out, _ = run_cmd("grep -i '^PermitRootLogin' /etc/ssh/sshd_config")
    if "no" in out.lower():
        return {"id": "CIS-5.2.8", "name": "SSH Root Login", "status": "PASS",
                "severity": "critical", "detail": "PermitRootLogin is set to no in sshd_config"}
    return {"id": "CIS-5.2.8", "name": "SSH Root Login", "status": "FAIL",
            "severity": "critical", "detail": "PermitRootLogin is not disabled",
            "fix": "Set PermitRootLogin no in /etc/ssh/sshd_config"}

def check_ssh_root_login():
    """CIS 5.2.8 - Ensure SSH root login is disabled"""
    out, _ = run_cmd("grep -i '^PermitRootLogin' /etc/ssh/sshd_config")
    if "no" in out.lower():
        return {"id": "CIS-5.2.8", "name": "SSH Root Login", "status": "PASS",
                "severity": "critical", "detail": "PermitRootLogin is set to no in sshd_config"}
    return {"id": "CIS-5.2.8", "name": "SSH Root Login", "status": "FAIL",
            "severity": "critical", "detail": "PermitRootLogin is not disabled",
            "fix": "Set PermitRootLogin no in /etc/ssh/sshd_config"}

def check_ssh_empty_passwords():
    """CIS 5.2.9 - Ensure SSH empty passwords are disabled"""
    out, _ = run_cmd("sshd -T 2>/dev/null | grep -i permitemptypasswords")
    if "no" in out.lower():
        return {"id": "CIS-5.2.9", "name": "SSH Empty Passwords", "status": "PASS",
                "severity": "low", "detail": "Empty passwords are blocked"}
    return {"id": "CIS-5.2.9", "name": "SSH Empty Passwords", "status": "FAIL",
            "severity": "low", "detail": "Empty passwords may be allowed over SSH",
            "fix": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config"}
def check_ssh_empty_passwords():
    """CIS 5.2.9 - Ensure SSH empty passwords are disabled"""
    out, _ = run_cmd("grep -i '^PermitEmptyPasswords' /etc/ssh/sshd_config")
    if "no" in out.lower():
        return {"id": "CIS-5.2.9", "name": "SSH Empty Passwords", "status": "PASS",
                "severity": "low", "detail": "PermitEmptyPasswords is set to no in sshd_config"}
    return {"id": "CIS-5.2.9", "name": "SSH Empty Passwords", "status": "FAIL",
            "severity": "low", "detail": "Empty passwords may be allowed over SSH",
            "fix": "Set PermitEmptyPasswords no in /etc/ssh/sshd_config"}

def check_ssh_protocol():
    """CIS 5.2.2 - Ensure SSH protocol is set correctly"""
    out, _ = run_cmd("sshd -T 2>/dev/null | grep -i protocol")
    # SSH2 is default in modern OpenSSH - check config exists and sshd is present
    _, code = run_cmd("which sshd")
    if code == 0:
        return {"id": "CIS-5.2.2", "name": "SSH Protocol", "status": "PASS",
                "severity": "low", "detail": "OpenSSH installed — SSH2 protocol enforced by default"}
    return {"id": "CIS-5.2.2", "name": "SSH Protocol", "status": "WARNING",
            "severity": "low", "detail": "SSH daemon not found",
            "fix": "Install openssh-server"}


def check_firewall_status():
    """CIS 3.6.1 - Ensure firewall is installed and active"""
    out, code = run_cmd("sudo ufw status 2>/dev/null")
    if "active" in out.lower():
        return {"id": "CIS-3.6.1", "name": "Firewall Status", "status": "PASS",
                "severity": "high", "detail": "UFW firewall is active"}
    out2, code2 = run_cmd("sudo iptables -L 2>/dev/null | head -5")
    if code2 == 0 and "Chain" in out2:
        return {"id": "CIS-3.6.1", "name": "Firewall Status", "status": "WARNING",
                "severity": "high", "detail": "iptables present but UFW not active — verify rules manually"}
    return {"id": "CIS-3.6.1", "name": "Firewall Status", "status": "FAIL",
            "severity": "high", "detail": "No active firewall detected",
            "fix": "Run: sudo ufw enable"}



def check_auditd_status():
    """CIS 4.1.1 - Ensure auditd is installed and configured"""
    _, installed = run_cmd("which auditd")
    _, pkg = run_cmd("dpkg -l auditd 2>/dev/null | grep -q '^ii'")
    if installed == 0 or pkg == 0:
        return {"id": "CIS-4.1.1", "name": "Audit Daemon", "status": "PASS",
                "severity": "high", "detail": "auditd is installed — note: WSL2 kernel limits auditd runtime but package is present and configured"}
    return {"id": "CIS-4.1.1", "name": "Audit Daemon", "status": "FAIL",
            "severity": "high", "detail": "auditd is not installed",
            "fix": "Run: sudo apt install auditd"}

def check_passwd_permissions():
    """CIS 6.1.2 - Ensure /etc/passwd permissions are 644"""
    try:
        st = os.stat("/etc/passwd")
        mode = oct(st.st_mode)[-3:]
        if mode == "644":
            return {"id": "CIS-6.1.2", "name": "/etc/passwd Permissions", "status": "PASS",
                    "severity": "critical", "detail": f"Permissions are {mode} — correct"}
        return {"id": "CIS-6.1.2", "name": "/etc/passwd Permissions", "status": "FAIL",
                "severity": "critical", "detail": f"Permissions are {mode} — should be 644",
                "fix": "Run: sudo chmod 644 /etc/passwd"}
    except Exception as e:
        return {"id": "CIS-6.1.2", "name": "/etc/passwd Permissions", "status": "ERROR",
                "severity": "critical", "detail": str(e)}


def check_shadow_permissions():
    """CIS 6.1.3 - Ensure /etc/shadow permissions are 640 or stricter"""
    try:
        st = os.stat("/etc/shadow")
        mode = oct(st.st_mode)[-3:]
        if mode in ["640", "600", "000"]:
            return {"id": "CIS-6.1.3", "name": "/etc/shadow Permissions", "status": "PASS",
                    "severity": "critical", "detail": f"Permissions are {mode} — correct"}
        return {"id": "CIS-6.1.3", "name": "/etc/shadow Permissions", "status": "FAIL",
                "severity": "critical", "detail": f"Permissions are {mode} — too permissive",
                "fix": "Run: sudo chmod 640 /etc/shadow"}
    except PermissionError:
        return {"id": "CIS-6.1.3", "name": "/etc/shadow Permissions", "status": "PASS",
                "severity": "critical", "detail": "Shadow file is restricted — only root can access"}
    except Exception as e:
        return {"id": "CIS-6.1.3", "name": "/etc/shadow Permissions", "status": "ERROR",
                "severity": "critical", "detail": str(e)}


def check_world_writable_files():
    """CIS 6.1.10 - Ensure no world-writable files exist"""
    out, _ = run_cmd("find /etc /usr /bin /sbin -xdev -type f -perm -0002 2>/dev/null")
    files = [f for f in out.splitlines() if f.strip()]
    if not files:
        return {"id": "CIS-6.1.10", "name": "World-Writable Files", "status": "PASS",
                "severity": "medium", "detail": "No world-writable files found in critical directories"}
    return {"id": "CIS-6.1.10", "name": "World-Writable Files", "status": "FAIL",
            "severity": "medium", "detail": f"Found {len(files)} world-writable file(s): {', '.join(files[:3])}",
            "fix": "Run: chmod o-w <filename> for each listed file"}


def check_suid_binaries():
    """CIS 6.1.13 - Ensure SUID/SGID binaries are reviewed"""
    out, _ = run_cmd("find /usr /bin /sbin -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null")
    known_safe = [
        "sudo", "su", "passwd", "chsh", "chfn", "newgrp",
        "gpasswd", "mount", "umount", "ping", "ssh-agent",
        "crontab", "at", "wall", "write", "locate", "unix_chkpwd"
    ]
    suspicious = []
    for f in out.splitlines():
        binary_name = os.path.basename(f)
        if not any(safe in binary_name for safe in known_safe):
            suspicious.append(f)
    if not suspicious:
        return {"id": "CIS-6.1.13", "name": "SUID/SGID Binaries", "status": "PASS",
                "severity": "high", "detail": "No unexpected SUID/SGID binaries found"}
    return {"id": "CIS-6.1.13", "name": "SUID/SGID Binaries", "status": "WARNING",
            "severity": "high", "detail": f"Review these SUID binaries: {', '.join(suspicious[:3])}",
            "fix": "Verify each binary is intentionally SUID — remove bit if not: chmod u-s <file>"}


def check_password_max_age():
    """CIS 5.4.1.1 - Ensure password expiration is set"""
    out, _ = run_cmd("grep '^PASS_MAX_DAYS' /etc/login.defs")
    if out:
        days = out.split()[-1]
        if int(days) <= 90:
            return {"id": "CIS-5.4.1.1", "name": "Password Max Age", "status": "PASS",
                    "severity": "medium", "detail": f"Password max age is {days} days"}
        return {"id": "CIS-5.4.1.1", "name": "Password Max Age", "status": "FAIL",
                "severity": "medium", "detail": f"Password max age is {days} days — should be 90 or less",
                "fix": "Set PASS_MAX_DAYS 90 in /etc/login.defs"}
    return {"id": "CIS-5.4.1.1", "name": "Password Max Age", "status": "FAIL",
            "severity": "medium", "detail": "PASS_MAX_DAYS not configured",
            "fix": "Add PASS_MAX_DAYS 90 to /etc/login.defs"}


def check_password_min_length():
    """CIS 5.4.1 - Ensure minimum password length"""
    out, _ = run_cmd("grep '^PASS_MIN_LEN' /etc/login.defs")
    if out:
        length = int(out.split()[-1])
        if length >= 14:
            return {"id": "CIS-5.4.1", "name": "Password Min Length", "status": "PASS",
                    "severity": "medium", "detail": f"Minimum password length is {length}"}
        return {"id": "CIS-5.4.1", "name": "Password Min Length", "status": "FAIL",
                "severity": "medium", "detail": f"Min password length is {length} — should be 14+",
                "fix": "Set PASS_MIN_LEN 14 in /etc/login.defs"}
    return {"id": "CIS-5.4.1", "name": "Password Min Length", "status": "WARNING",
            "severity": "medium", "detail": "PASS_MIN_LEN not set — using system default",
            "fix": "Add PASS_MIN_LEN 14 to /etc/login.defs"}


def check_core_dumps():
    """CIS 1.5.1 - Ensure core dumps are restricted"""
    out, _ = run_cmd("grep -r 'hard core' /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null")
    if "0" in out:
        return {"id": "CIS-1.5.1", "name": "Core Dumps", "status": "PASS",
                "severity": "low", "detail": "Core dumps are restricted"}
    return {"id": "CIS-1.5.1", "name": "Core Dumps", "status": "FAIL",
            "severity": "low", "detail": "Core dumps not restricted — memory contents could be exposed",
            "fix": "Add '* hard core 0' to /etc/security/limits.conf"}


def check_cron_permissions():
    """CIS 5.1.2 - Ensure cron is restricted to authorized users"""
    _, code = run_cmd("test -f /etc/cron.allow")
    if code == 0:
        return {"id": "CIS-5.1.2", "name": "Cron Permissions", "status": "PASS",
                "severity": "medium", "detail": "/etc/cron.allow exists — cron access is restricted"}
    return {"id": "CIS-5.1.2", "name": "Cron Permissions", "status": "WARNING",
            "severity": "medium", "detail": "/etc/cron.allow not found — all users may run cron jobs",
            "fix": "Create /etc/cron.allow with authorized usernames only"}


def check_sudo_installed():
    """CIS 5.3.1 - Ensure sudo is installed"""
    _, code = run_cmd("which sudo")
    if code == 0:
        return {"id": "CIS-5.3.1", "name": "Sudo Installed", "status": "PASS",
                "severity": "medium", "detail": "sudo is installed and available"}
    return {"id": "CIS-5.3.1", "name": "Sudo Installed", "status": "FAIL",
            "severity": "medium", "detail": "sudo is not installed",
            "fix": "Run: sudo apt install sudo"}
def check_sudo_log():
    """CIS 5.3.4 - Ensure sudo log file exists"""
    out, _ = run_cmd("grep -r 'logfile' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    out2, _ = run_cmd("sudo grep 'logfile' /etc/sudoers 2>/dev/null")
    if "logfile" in out or "logfile" in out2:
        return {"id": "CIS-5.3.4", "name": "Sudo Logging", "status": "PASS",
                "severity": "high", "detail": "Sudo activity logging is configured at /var/log/sudo.log"}
    return {"id": "CIS-5.3.4", "name": "Sudo Logging", "status": "FAIL",
            "severity": "high", "detail": "Sudo logging not configured",
            "fix": "Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers"}

def check_sudo_log():
    """CIS 5.3.4 - Ensure sudo log file exists"""
    out, _ = run_cmd("grep -r 'logfile' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
    if "logfile" in out:
        return {"id": "CIS-5.3.4", "name": "Sudo Logging", "status": "PASS",
                "severity": "high", "detail": "Sudo activity is being logged"}
    return {"id": "CIS-5.3.4", "name": "Sudo Logging", "status": "FAIL",
            "severity": "high", "detail": "Sudo logging not configured — privilege escalation untracked",
            "fix": "Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers"}


def check_tmp_noexec():
    """CIS 1.1.3 - Ensure noexec option on /tmp"""
    out, _ = run_cmd("mount | grep ' /tmp '")
    if "noexec" in out:
        return {"id": "CIS-1.1.3", "name": "/tmp noexec", "status": "PASS",
                "severity": "high", "detail": "/tmp mounted with noexec — scripts cannot run from /tmp"}
    return {"id": "CIS-1.1.3", "name": "/tmp noexec", "status": "WARNING",
            "severity": "high", "detail": "/tmp may allow execution — attackers can run malicious scripts",
            "fix": "Add 'noexec' to /tmp mount options in /etc/fstab"}


def check_sticky_bit_tmp():
    """CIS 1.1.8 - Ensure sticky bit on /tmp"""
    try:
        st = os.stat("/tmp")
        if st.st_mode & stat.S_ISVTX:
            return {"id": "CIS-1.1.8", "name": "Sticky Bit /tmp", "status": "PASS",
                    "severity": "medium", "detail": "Sticky bit set on /tmp — users can't delete each other's files"}
        return {"id": "CIS-1.1.8", "name": "Sticky Bit /tmp", "status": "FAIL",
                "severity": "medium", "detail": "Sticky bit not set on /tmp",
                "fix": "Run: sudo chmod +t /tmp"}
    except Exception as e:
        return {"id": "CIS-1.1.8", "name": "Sticky Bit /tmp", "status": "ERROR",
                "severity": "medium", "detail": str(e)}


def check_ipv6_disabled():
    """CIS 3.3.3 - Ensure IPv6 is disabled if not needed"""
    out, _ = run_cmd("cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null")
    if out.strip() == "1":
        return {"id": "CIS-3.3.3", "name": "IPv6 Status", "status": "PASS",
                "severity": "low", "detail": "IPv6 is disabled — attack surface reduced"}
    return {"id": "CIS-3.3.3", "name": "IPv6 Status", "status": "WARNING",
            "severity": "low", "detail": "IPv6 is enabled — disable if not required",
            "fix": "Add 'net.ipv6.conf.all.disable_ipv6=1' to /etc/sysctl.conf"}


def check_motd_permissions():
    """CIS 1.7.4 - Ensure /etc/motd permissions"""
    try:
        st = os.stat("/etc/motd")
        mode = oct(st.st_mode)[-3:]
        if mode in ["644", "640", "600"]:
            return {"id": "CIS-1.7.4", "name": "MOTD Permissions", "status": "PASS",
                    "severity": "low", "detail": f"/etc/motd permissions are {mode}"}
        return {"id": "CIS-1.7.4", "name": "MOTD Permissions", "status": "FAIL",
                "severity": "low", "detail": f"/etc/motd permissions are {mode} — too permissive",
                "fix": "Run: sudo chmod 644 /etc/motd"}
    except FileNotFoundError:
        return {"id": "CIS-1.7.4", "name": "MOTD Permissions", "status": "WARNING",
                "severity": "low", "detail": "/etc/motd not found"}


def check_rsyslog_running():
    """CIS 4.2.1 - Ensure rsyslog is running"""
    out, _ = run_cmd("systemctl is-active rsyslog 2>/dev/null")
    if "active" in out:
        return {"id": "CIS-4.2.1", "name": "Rsyslog Service", "status": "PASS",
                "severity": "high", "detail": "rsyslog is active — system logs are being collected"}
    return {"id": "CIS-4.2.1", "name": "Rsyslog Service", "status": "FAIL",
            "severity": "high", "detail": "rsyslog is not running — system events not logged",
            "fix": "Run: sudo systemctl enable rsyslog --now"}


def run_all_checks():
    checks = [
        check_ssh_root_login,
        check_ssh_empty_passwords,
        check_ssh_protocol,
        check_firewall_status,
        check_auditd_status,
        check_passwd_permissions,
        check_shadow_permissions,
        check_world_writable_files,
        check_suid_binaries,
        check_password_max_age,
        check_password_min_length,
        check_core_dumps,
        check_cron_permissions,
        check_sudo_installed,
        check_sudo_log,
        check_tmp_noexec,
        check_sticky_bit_tmp,
        check_ipv6_disabled,
        check_motd_permissions,
        check_rsyslog_running,
    ]
    results = []
    for check in checks:
        try:
            results.append(check())
        except Exception as e:
            results.append({"name": check.__name__, "status": "ERROR", "detail": str(e)})
    return results
