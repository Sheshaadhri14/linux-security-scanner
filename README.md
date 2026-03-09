# 🔐 Linux Security Compliance Scanner

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Ansible](https://img.shields.io/badge/Ansible-2.16-red)
![CIS Benchmark](https://img.shields.io/badge/CIS-Benchmark-orange)
![License](https://img.shields.io/badge/License-MIT-green)

A production-grade Linux security auditing tool that scans systems against
**CIS Benchmark controls**, generates compliance reports, and automatically
hardens misconfigurations using **Ansible playbooks** — inspired by Red Hat
Insights and OpenSCAP.

---

## 🎯 What It Does

- Runs **20 CIS Benchmark security checks** across SSH, filesystem,
  password policy, logging, and network configuration
- Generates a **compliance score** with PASS / FAIL / WARNING per check
- Produces a **JSON + HTML compliance report** with severity mapping
- **Auto-hardens** all failures via an Ansible playbook
- Runs on every commit via **GitHub Actions CI pipeline**

---

## 📊 Sample Output
```
COMPLIANCE SCORE : 80.0%
PASSED           : 16/20
FAILED           : 1
WARNINGS         : 3
RISK LEVEL       : LOW RISK
```

---

## 🔍 Security Checks Covered

| CIS ID | Check | Severity |
|--------|-------|----------|
| CIS-5.2.8 | SSH Root Login Disabled | Critical |
| CIS-5.2.9 | SSH Empty Passwords Blocked | Low |
| CIS-3.6.1 | Firewall Active | High |
| CIS-4.1.1 | Audit Daemon Running | High |
| CIS-6.1.2 | /etc/passwd Permissions | Critical |
| CIS-6.1.3 | /etc/shadow Permissions | Critical |
| CIS-6.1.10 | No World-Writable Files | Medium |
| CIS-6.1.13 | SUID/SGID Binaries Reviewed | High |
| CIS-5.4.1.1 | Password Max Age 90 Days | Medium |
| CIS-5.4.1 | Password Min Length 14 | Medium |
| CIS-1.5.1 | Core Dumps Restricted | Low |
| CIS-5.1.2 | Cron Access Restricted | Medium |
| CIS-5.3.1 | Sudo Installed | Medium |
| CIS-5.3.4 | Sudo Logging Enabled | High |
| CIS-1.1.3 | /tmp noexec Mounted | High |
| CIS-1.1.8 | Sticky Bit on /tmp | Medium |
| CIS-3.3.3 | IPv6 Disabled if Unused | Low |
| CIS-1.7.4 | MOTD Permissions | Low |
| CIS-4.2.1 | Rsyslog Running | High |
| CIS-5.2.2 | SSH Protocol Secure | Low |

---

## 🚀 Quick Start

### Prerequisites
- Linux / WSL2 (Ubuntu 22.04+)
- Python 3.10+
- Ansible 2.14+

### Install
```bash
git clone https://github.com/YOUR_USERNAME/linux-security-scanner
cd linux-security-scanner
pip3 install jinja2 pyyaml --break-system-packages
```

### Run Scanner
```bash
cd scanner
python3 scan.py
```

### Run Auto-Hardening
```bash
sudo ansible-playbook playbooks/harden.yml
```

### View Report
Open `reports/compliance_report.html` in your browser.

---

## 🏗️ Project Structure
```
linux-security-scanner/
├── scanner/
│   ├── checks.py        # 20 CIS Benchmark security checks
│   ├── scan.py          # Main runner + terminal output
│   └── report.py        # HTML + JSON report generator
├── playbooks/
│   └── harden.yml       # Ansible auto-hardening playbook
├── reports/             # Generated compliance reports
├── config.yaml          # Thresholds and severity config
└── .github/workflows/
    └── ci.yml           # GitHub Actions CI pipeline
```

---

## 🔧 Tech Stack

| Technology | Purpose |
|------------|---------|
| Python 3.12 | Security check engine + report generation |
| Bash | System command execution |
| Ansible | Automated hardening playbooks |
| YAML | Configuration and playbook definitions |
| Jinja2 | HTML report templating |
| GitHub Actions | CI/CD pipeline |

---

## 💡 Inspired By

- [Red Hat Insights](https://www.redhat.com/en/technologies/management/insights)
- [OpenSCAP](https://www.open-scap.org/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

---

## 👤 Author

**Sri Sheshaadhri R** 
