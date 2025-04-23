# 🔍 PowerShell Nmap Multi-IP Scanner

This PowerShell script performs automated Nmap scans on multiple user-defined IP addresses. It collects service information and launches targeted NSE (Nmap Scripting Engine) scans for common services like SSH, HTTP, FTP, SMB, RDP, and more.

---

## 🚀 Features

- 🧠 User-friendly prompts to input any number of IPs interactively.
- 📦 Batch Nmap scans with:
  - Full port discovery
  - Service/version detection (`-sV`, `-sC`)
- 🎯 Targeted follow-up NSE scans on:
  - SSH (`ssh2-enum-algos`, `ssh-auth-methods`)
  - HTTP/HTTPS (`ssl-enum-ciphers`, `ssl-cert`)
  - FTP (`ftp-anon`, `ftp-bounce`, `ftp-syst`)
  - SMB (`smb-*`)
  - RDP (`rdp-enum-encryption`, `rdp-ntlm-info`)
  - DNS, SMTP, NTP, Telnet, SNMP
- 📁 Organized output:
  - Creates a folder per IP address
  - Saves XML, Nmap, GNMAP, and NSE scan results by service

---

## 💻 Requirements

- **PowerShell**
- **Nmap** must be installed and added to system PATH.

---

## 📦 Usage

1. Open a PowerShell terminal.
2. Run the script:

```powershell
.\script.ps1
```

3. Enter the number of IPs and input each IP when prompted.
4. Wait while the script performs full port scans and follows up with targeted NSE scans for discovered services.

---

## 🗂 Output

- Scan results are saved in folders like `192.168.1.10-scan-results`
- Inside each folder:
  - `.nmap`, `.xml`, `.gnmap` results
  - NSE results for each detected service by port

Example:
```
192.168.1.10-scan-results/
├── 192.168.1.10-all-SYN.nmap
├── 192.168.1.10-ssl-ciphers-443.txt
├── 192.168.1.10-ftp-enum-21.txt
└── ...
```

---
