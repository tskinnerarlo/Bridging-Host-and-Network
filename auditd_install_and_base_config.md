# Base auditd install on Ubuntu 20.04

Here’s a clean, repeatable way to install and harden auditd on Ubuntu 20.04, with sensible defaults and a starter rule set. This assumes you’re using sudo and a stock Ubuntu kernel.

**1) Install the packages**

```bash
sudo apt update
sudo apt install -y auditd audispd-plugins
```

**2) Enable and start the service**
```bash
sudo systemctl enable auditd
sudo systemctl start auditd
sudo systemctl status auditd --no-pager
```

**3) Basic daemon settings (log size, rotation, fail-safes)**
<br>Edit ```/etc/audit/auditd.conf``` and tune these (examples shown):
```bash
#
# This file controls the configuration of the audit daemon
#

local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = ENRICHED
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 200
num_logs = 10
priority_boost = 4
name_format = HOSTNAME          # or FQDN if you prefer
##name = mydomain
max_log_file_action = ROTATE    # (or keep_logs for forensics-first)
space_left = 15%                # or MB value, e.g., 1024
space_left_action = SYSLOG      # (or email, exec, etc.)
verify_email = yes
action_mail_acct = root
admin_space_left = 5%
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
use_libwrap = yes
##tcp_listen_port = 60
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
transport = TCP
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
distribute_network = no
q_depth = 1200
overflow_action = SYSLOG
max_restarts = 10
plugin_dir = /etc/audit/plugins.d
end_of_event_timeout = 2
```

**4) Add a sane starter ruleset**
<br>Create /etc/audit/rules.d/10-base.rules with this content (tuned for PSA-style “who changed what & when” without going overboard):

```bash
# Reset existing rules, set backlog and failure mode
-D
-b 8192
-f 1

## --- Identity & auth storefronts ---
-w /etc/passwd   -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/group    -p wa -k identity
-w /etc/gshadow  -p wa -k identity
-w /etc/sudoers  -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

## --- SSH & security-critical configs ---
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/ -p wa -k security-conf

## --- Time changes (privilege & incident investigations) ---
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## --- Kernel module loads/unloads ---
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
-a always,exit -F arch=b32 -S init_module,delete_module -k modules

## --- Mount operations ---
-a always,exit -F arch=b64 -S mount,umount2 -k mounts
-a always,exit -F arch=b32 -S mount,umount2 -k mounts

## --- Network environment changes ---
-w /etc/hosts -p wa -k network
-w /etc/hostname -p wa -k network
-w /etc/resolv.conf -p wa -k network

## --- Privilege use (successful/failed) ---
#-w /var/log/sudo.log -p wa -k sudo-log  # if present (on some systems)
-a always,exit -F arch=b64 -S setuid,setgid,setfsuid,setfsgid -k priv-change
-a always,exit -F arch=b32 -S setuid,setgid,setfsuid,setfsgid -k priv-change

## --- Optional: Process exec visibility (heavier) ---
# Uncomment if you want broad exec tracking (more volume).
#-a always,exit -F arch=b64 -S execve,execveat -k exec
#-a always,exit -F arch=b32 -S execve,execveat -k exec

## --- Lock rules after validation (add only when you’re happy) ---
# -e 2

```

*Notes* <br>
• Keep both b64 and b32 syscalls; even on x86_64, some 32-bit paths exist.
<br>• The exec rules are powerful but noisy—start without them, or scope to select binaries.
<br>• Add custom -w watches for critical app configs unique to your environment.

*5) Load the rules and verify*

```bash
# Compile & load all files in /etc/audit/rules.d/*.rules
sudo augenrules --load

# Confirm rules and audit status
sudo auditctl -l
sudo auditctl -s
```
Expected: enabled 1, your backlog limit, and the rules listed.

**6) Ensure auditing is on from boot (recommended)**
<br>Make the kernel enable audit early and give it a bigger backlog in case of bursts:
```bash
sudo sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192 /' /etc/default/grub
sudo update-grub
sudo reboot
```
After reboot:
```bash
sudo auditctl -s
```

**7) (Optional) Forward or mirror to syslog/SIEM**
<br>If you want duplicates in syslog for correlation, enable the audisp syslog plugin:
```bash
# Check plugin config
grep -R "active" /etc/audisp/plugins.d/
# Typically: /etc/audisp/plugins.d/syslog.conf -> set active = yes
sudo sed -i 's/^active.*/active = yes/' /etc/audisp/plugins.d/syslog.conf
sudo systemctl restart auditd
```

**9) Ongoing care**
<br> 
* Rotation & space: auditd rotates on its own per auditd.conf. Size ceilings + space actions prevent outages.

* Changes safely: avoid -e 2 (immutable) until your rules are proven in prod—once set, you need a reboot to change rules.

* Performance: if you later add execve* rules, consider excluding noisy paths (e.g., package managers) or using keyed rules to filter in your SIEM.
