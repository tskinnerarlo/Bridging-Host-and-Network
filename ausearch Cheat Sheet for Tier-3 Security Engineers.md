
This Tier‑3–level guide focuses on high‑signal filters, event stitching, and repeatable hunt recipes for **ausearch** over Linux **auditd** logs.

---

## Core Concepts (Fast Refresher)

- **auditd events = bundles of records** sharing the same `serial` (the number after the timestamp in `msg=audit(...)`). A single “event” usually contains `SYSCALL` + `EXECVE` + `CWD` + `PATH` (+ `PROCTITLE`, `SOCKADDR`, etc.).
- **ausearch** filters **server‑side** (no grep required), returning only matching events (all records for each match).
- Filters are **ANDed** together; multiple `-m` values are **ORed** within the message‑type filter.

---

## Most‑Useful Switches (with Notes)

- `-i` / `--interpret` — resolve IDs to names (UID→user, GID→group, SIDs, syscall names, hex→ASCII in `PROCTITLE`).
- `--start` / `--end` — time window; accepts natural strings: `recent`, `today`, `yesterday`, `this-week`, `this-month`, or absolute `"YYYY-MM-DD HH:MM:SS"`.
- `-k <key>` / `--key <key>` — match events tagged by your audit rules (`-k` in `auditctl`/rules.d).
- `-m <type>` / `--message <type>` — event type(s), e.g. `SYSCALL`, `EXECVE`, `USER_LOGIN`, `AVC`, `CWD`, `PATH`, `PROCTITLE`, `SOCKADDR`. Repeat `-m` to **OR**.
- `--success yes|no` — filter by syscall success (from `SYSCALL success=`).
- `-p <pid>` / `--pid <pid>` — process ID.
- `--ppid <ppid>` — parent process ID.
- `-x <path>` / `--exe <path>` — executable path (from `exe=` in `SYSCALL`).
- `-c <comm>` / `--comm <comm>` — command name (from `comm=`).
- `-f <path>` / `--file <path>` — file path (matches `PATH name=`).
- `-ua <auid>` / `--auid <auid>` — audit user ID (login UID).
- `-ui <uid>` / `--uid <uid>` — effective user ID at the time of the syscall.
- `-sc <syscall>` / `--syscall <syscall>` — syscall name or number (e.g., `open`, `openat`, `execve`, `connect`).
- `-a <serial>` / `--event <serial>` — pull a specific event by serial number.
- `--node <hostname>` — limit to events from a specific audited node (useful with remote collectors).
- `--line-buffered` — stream results as they’re found (handy when piping).

> **Tip:** Use **`-i` during analysis**, but drop `-i` for automation/parsing since names can vary across hosts.

---

## Quick Patterns You’ll Use a Lot

### Time Windows
```bash
ausearch -i --start today
ausearch -i --start "2025-09-16 14:00:00" --end "2025-09-16 15:00:00"
ausearch -i --start recent  # last ~10 minutes
```

### By Audit Rule Key
```bash
ausearch -i -k curl_exec --start today
```

### By User / AUID
```bash
ausearch -i --uid root --start today
ausearch -i --auid 1000 --start today
```

### By Process / Executable / Command Name
```bash
ausearch -i --pid 4242 --start recent
ausearch -i --exe /usr/bin/curl --start today
ausearch -i --comm sshd --start today
```

### By File Path
```bash
ausearch -i --file /etc/sudoers --start yesterday
```

### By Syscall and Success
```bash
ausearch -i -m SYSCALL --syscall execve --success yes --start today
ausearch -i -m SYSCALL --syscall connect --start recent
```

### Pull the Full Event Once You Have a Serial
```bash
ausearch -i --event 123456789
```

---

## Event Stitching Workflow (Serials & Record Types)

1. **Find candidate events** with a coarse filter (key, user, exe, time).
2. **Note the `msg=audit(TS:SERIAL)`** in output; that SERIAL ties all records.
3. **Re-query by serial** to get the complete bundle:
   ```bash
   ausearch -i --event SERIAL
   ```
4. If you want one record type (e.g., just `EXECVE` lines) from those events, add `-m EXECVE`.

---

## Deep‑Dive Hunt Recipes (Copy/Paste)

### 1) Who Changed a Sensitive File?
```bash
# Any writes to /etc/ssh/sshd_config today
ausearch -i --file /etc/ssh/sshd_config --start today   | ausearch -i -m SYSCALL --success yes --syscall open,openat,rename,unlink,truncate,chmod,chown
```

### 2) All Executions of “curl” with Args (See `EXECVE` & `PROCTITLE`)
```bash
ausearch -i --exe /usr/bin/curl --start today -m EXECVE,PROCTITLE
```

### 3) Outbound Network Connects by Interactive Users (T1071 Pivot)
```bash
ausearch -i -m SYSCALL --syscall connect --success yes --start "1 hour ago"   | grep -E "type=SOCKADDR|type=SYSCALL"
```

### 4) Suspected Lateral Movement: Which TTY/Host Did `root` Use?
```bash
# Successful root logins (PAM)
ausearch -i -m USER_LOGIN --success yes --uid root --start yesterday
```

### 5) End‑to‑End Execution Chain for a PID
```bash
ausearch -i --pid 31337 --start yesterday -m SYSCALL,EXECVE,CWD,PATH,PROCTITLE
```

### 6) All Events from a Specific Rule Key, Summarized
```bash
ausearch --start today -k http_large_send_curl   | aureport -i -au   # or -f (files), -x (executables), -p (processes)
```

---

## Power Techniques (Tier‑3 Tips)

- **Success/Failure Logic:** Many hunts need `--success no` (e.g., brute‑force or tamper attempts).
  ```bash
  ausearch -i -m USER_CMD --success no --start today
  ```
- **Multiple Message Types:** OR within `-m`.
  ```bash
  ausearch -i -m SYSCALL -m AVC --start today
  ```
- **Narrow to Nodes:** When using a central collector.
  ```bash
  ausearch -i --node web-03 --start today -k tls_rules
  ```
- **Path Wildcards:** `--file` matches exact paths in `PATH name=`. For directory‑scoped hunts, add keys in your rules (e.g., `-F dir=/var/www -k web_tree`) and search by `-k`.
- **High‑Volume Triage:** Pipe to `aureport` for aggregation.
  ```bash
  ausearch --start today -m SYSCALL --syscall execve | aureport -x -i
  ```
- **Reverse Time:** Add `-r` to show most recent first.

---

## Interpreting Common Record Fields (Quick Map)

- **SYSCALL:** `exe=`, `comm=`, `pid=`, `ppid=`, `uid=`, `auid=`, `success=`, `syscall=`, `arch=`, `ses=` (login session), `tty=`.
- **EXECVE:** `argc=`, `a0="cmd"`, `a1="arg1"`, … (command‑line arguments).
- **PROCTITLE:** hex‑encoded argv (redundant but sometimes more complete).
- **CWD:** current working directory.
- **PATH:** one per file touched; includes `name=`, `nametype=`, `inode=`, `mode=`.
- **SOCKADDR:** `saddr=` (decoded with `-i`), showing remote IP/port for `connect`.

---

## Validation / Test Cases (Spin Up Quickly)

> If you need test events, temporarily add a rule and generate activity.

### 1) Test EXECVE Capture
```bash
# add temp rule
sudo auditctl -a always,exit -F arch=b64 -S execve -k test_exec
# generate
/bin/echo hello >/dev/null
# verify
ausearch -i -k test_exec --start recent -m EXECVE,PROCTITLE
```

### 2) Test File Write Capture (openat with write)
```bash
sudo auditctl -a always,exit -F arch=b64 -S openat -F perm=w -F dir=/tmp -k test_write
echo hi >> /tmp/auditd_test.txt
ausearch -i -k test_write --start recent -m SYSCALL,PATH,CWD
```

### 3) Test Outbound Connect Capture
```bash
sudo auditctl -a always,exit -F arch=b64 -S connect -k test_connect
curl -s https://example.com >/dev/null
ausearch -i -k test_connect --start recent -m SYSCALL,SOCKADDR
```

Remove temp rules when done:
```bash
sudo auditctl -D
# or reload your persisted rules via augenrules
sudo augenrules --load
```

---

## Troubleshooting & Gotchas

- **No results?** Check time window (`--start/--end`), node filtering, and whether your **audit rules** actually log the thing you’re hunting.
- **Missing `EXECVE`?** You only get `EXECVE` if you log `execve` syscalls. Add a scoped rule (e.g., to `/usr/bin/curl` or to `auid>=1000`) to keep overhead down.
- **Hex in `PROCTITLE`:** Always add `-i` so it’s auto‑decoded; otherwise you’ll see hex blobs.
- **High volume:** Prefer searching by **keys** (`-k`) that you assign thoughtfully in rules. Keys are the best handles for near‑real‑time triage.

---

## Handy One‑Liners

```bash
# All failed logins in last day
ausearch -i -m USER_LOGIN --success no --start yesterday

# All sudo invocations with full args
ausearch -i -m USER_CMD --comm sudo --start today

# Everything a specific login session did (ses=)
ausearch -i -m SYSCALL --start today | grep " ses=1234 " -A4

# Show top executables seen today (quick & dirty)
ausearch --start today -m SYSCALL --syscall execve   | grep -o ' exe=[^ ]*' | sort | uniq -c | sort -nr | head
```
