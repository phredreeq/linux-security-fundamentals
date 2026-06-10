# 🐧 Linux File System, Permissions and Security
### Understanding Linux Internals for SOC Analysts

---

## 🎯 What This Project Is About

This project covers the Linux security fundamentals
every SOC analyst must know before investigating
a compromised Linux server.

Understanding the file system layout, user privilege
levels, file permissions, SSH security and log
locations is essential for any incident investigation
on Linux systems.

Most enterprise servers run Linux. Understanding
how Linux works internally is not optional for
SOC analysts — it is foundational.

---

## Understanding the Linux File System

### The Directory Structure

Linux has one single directory tree starting
from root — written as /

Think of it like a hotel building:
/ = the entire hotel
Everything inside is a room or corridor

Key security directories:

| Directory | Contents | Security Relevance |
|---|---|---|
| /etc | All configuration files | SSH config, user accounts, passwords |
| /var/log | All system logs | Evidence of attacks and activity |
| /tmp | Temporary files — world writable | Attackers drop malware here |
| /root | Root user home directory | Highest privilege files |
| /home | Regular user directories | SSH keys, personal files |
| /bin | Essential system commands | Core utilities |

### Why /tmp is Dangerous

/tmp is writable by every user on the system
without special permissions. Attackers commonly
drop malware, scripts and tools in /tmp because:
- No special privilege needed to write here
- Files survive until reboot
- Often overlooked during investigations

Always check /tmp during incident investigation:
ls -la /tmp

---

## Users and Privilege Levels

### Three Types of Users

| Type | UID Range | Purpose |
|---|---|---|
| Root | 0 | Superuser — unlimited access |
| System users | 1-999 | Services — splunk, www-data |
| Regular users | 1000+ | Human users — fred, alice |

### Critical Security Files

/etc/passwd — user account information:
fred:x:1000:1000:Fred Agufenwa:/home/fred:/bin/bash

Fields: username:password:UID:GID:name:home:shell

The x means password stored in /etc/shadow
Everyone can read /etc/passwd

/etc/shadow — encrypted passwords:
Only root can read this file
Attackers target this for credential dumping

/etc/group — group memberships:
The sudo group gives temporary root privilege
Unexpected sudo group members = red flag

### SOC Red Flags in User Accounts

| Finding | Significance |
|---|---|
| New user with UID 0 | Attacker created second root account |
| Unknown user in sudo group | Privilege escalation achieved |
| User with no home directory | Possible backdoor account |
| System user with login shell | Service account being abused |

---

## File Permissions

### Permission Structure

Every file has three permission sets:
-rwxr-xr--

Position 1:    file type (- = file, d = directory)
Positions 2-4: owner permissions
Positions 5-7: group permissions
Positions 8-10: others permissions

### Permission Values

| Letter | Value | Meaning |
|---|---|---|
| r | 4 | Read |
| w | 2 | Write |
| x | 1 | Execute |
| - | 0 | No permission |

Add values for each group:
rwx = 4+2+1 = 7
r-x = 4+0+1 = 5
r-- = 4+0+0 = 4

### Critical Permission Sets

| Number | Meaning | Security Note |
|---|---|---|
| 777 | Everyone full access | DANGEROUS — never on sensitive files |
| 755 | Owner full, others read/execute | Normal for directories |
| 644 | Owner read/write, others read | Normal for files |
| 600 | Owner only | SSH keys, sensitive config |
| 400 | Read only | SSH private keys |

### SOC Red Flags in Permissions

777 on sensitive file = anyone can modify it
SUID bit on unexpected file = privilege escalation risk
World-writable directory outside /tmp = suspicious

---

## SSH Security

### Password vs Key Authentication

Password authentication:
- User types password to login
- Vulnerable to brute force attacks
- Should be disabled on hardened servers

Key authentication:
- Private key stays on your machine
- Public key goes on server authorized_keys
- Server challenges client mathematically
- Only correct private key solves the challenge
- Cannot be brute forced

### SSH Hardening Settings

File location: /etc/ssh/sshd_config

| Setting | Secure Value | Why |
|---|---|---|
| PermitRootLogin | no | Prevents direct root SSH access |
| PasswordAuthentication | no | Eliminates brute force possibility |
| MaxAuthTries | 3 | Limits automated attack attempts |
| LoginGraceTime | 30 | Reduces connection timeout window |

After changes restart SSH:
sudo systemctl restart sshd

### SOC Red Flags in SSH

| Finding | Significance |
|---|---|
| Unknown key in authorized_keys | Attacker has persistent access |
| Root login enabled | High risk — direct root access possible |
| Password auth enabled | Brute force attacks possible |
| Many failed auth.log entries | Brute force attack in progress |

---

## Linux Log Analysis

### Key Log Files

| Log File | Contains | When to Check |
|---|---|---|
| /var/log/auth.log | All authentication events | First — always |
| /var/log/syslog | General system events | Service issues |
| /var/log/dpkg.log | Software installations | Unauthorized installs |
| /var/log/kern.log | Kernel events | Rootkit detection |
| /var/log/ufw.log | Firewall events | Network attacks |

### Essential Log Commands

View entire log:
cat /var/log/auth.log

View last 100 lines:
tail -100 /var/log/auth.log

Watch log live in real time:
tail -f /var/log/auth.log

Search for failed logins:
grep "Failed password" /var/log/auth.log

Count failed attempts:
grep "Failed password" /var/log/auth.log | wc -l

Find attacking IPs and count attempts:
grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn

Search for specific IP:
grep "192.168.10.102" /var/log/auth.log

### Attack Patterns in Logs

Brute force attack pattern:
Failed password for root from attacker_ip
Failed password for root from attacker_ip
Failed password for root from attacker_ip
Accepted password for root from attacker_ip

Successful brute force = critical severity incident
Server is fully compromised

Username enumeration pattern:
Invalid user admin from attacker_ip
Invalid user test from attacker_ip
Invalid user postgres from attacker_ip

Attacker is guessing usernames that do not exist

Suspicious software installation:
2026-05-21 03:15:22 install nmap
2026-05-21 03:15:45 install netcat
2026-05-21 03:16:02 install hydra

Attack tools installed at 3AM = active compromise

### Why Real-Time Log Forwarding to Splunk Matters

Attackers delete local logs to cover tracks.
If logs are forwarded to Splunk in real time —
deleting local logs is useless.
Splunk already has every event.
This is why Day 13 pfSense log forwarding
and Day 17 Ubuntu log forwarding are critical.

---

## 🎯 MITRE ATT&CK Mapping

| Technique | ID | How Linux knowledge helps detect it |
|---|---|---|
| Valid Accounts | T1078 | Check /etc/passwd for unexpected users |
| SSH Authorized Keys | T1098.004 | Check authorized_keys for unknown keys |
| File Permissions Modification | T1222 | Monitor chmod on sensitive files |
| Clear Linux Logs | T1070.002 | Detect log gaps and deletions |
| Create Account | T1136 | Monitor /etc/passwd for new accounts |
| Brute Force | T1110 | Analyze auth.log for failed patterns |

---

## 🔍 Indicators of Compromise (IOCs)

| IOC | Where to Find It | Significance |
|---|---|---|
| New UID 0 user | /etc/passwd | Second root account created |
| Unknown authorized_keys entry | ~/.ssh/authorized_keys | Persistent backdoor access |
| Attack tools installed | /var/log/dpkg.log | Active compromise |
| 777 permissions on config files | ls -la /etc | Permissions deliberately loosened |
| Log file gaps | /var/log/auth.log | Log tampering |
| Unexpected sudo group member | /etc/group | Privilege escalation |
| Off-hours software installs | /var/log/dpkg.log | Unauthorized activity |

---

## 💡 Key Learnings

| Concept | What I Learned |
|---|---|
| Linux file system | Single tree from / — each directory has security purpose |
| UID 0 | Only root should have UID 0 — any other is backdoor |
| File permissions | Three groups — owner, group, others — r=4 w=2 x=1 |
| 777 danger | World writable — attacker can modify without escalation |
| SSH keys | Mathematical challenge — cannot be brute forced |
| authorized_keys | Attacker adds key for persistent access |
| /var/log/auth.log | First log to check in any Linux investigation |
| Real-time forwarding | Protects logs even if attacker deletes local copies |

---

## 🔗 Related Projects
- [pfSense Real-Time Log Forwarding](https://github.com/Phredreeq/pfsense-splunk-log-forwarding)
- [Brute Force Detection](https://github.com/Phredreeq/brute-force-detection)
- [pfSense Firewall Configuration](https://github.com/Phredreeq/pfsense-firewall-configuration)

---

## 🔗 References
- Linux file system hierarchy: tldp.org/LDP/Linux-Filesystem-Hierarchy
- SSH hardening guide: ssh.com/academy/ssh/sshd-config
- MITRE ATT&CK Linux techniques: attack.mitre.org
- Linux log files explained: ubuntu.com/server/docs/logging

---

## 👤 Author
Fredrick Agufenwa

Cybersecurity Student | SOC Analyst in Training
