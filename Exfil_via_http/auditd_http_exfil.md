# Http Exfil - The auditd rules
**Below is a practical, low-overhead auditd approach that covers both angles:**

- Uncommon HTTP verbs (e.g., PUT, PATCH, WebDAV) — captured at process execution time so you can read the command line and alert when a rare verb is used.

- Large POSTs / uploads — captured at the syscall level by watching socket send syscalls from curl/wget where the payload length exceeds a threshold.

Because auditd can’t regex-filter arbitrary argv text inline, we (A) log the relevant events with narrow rules, and (B) alert either in your SIEM (recommended) or with a tiny audisp filter (optional snippet provided) that inspects the EXECVE/PROCTITLE text to spot uncommon verbs.

Create /etc/audit/rules.d/http_exfil.rules with the following content, then load them (commands below).

```bash
###############################################################################
# A) EXECVE: capture curl/wget invocations by interactive users
#    - Lets you see command line (EXECVE/PROCTITLE) to spot verbs like PUT/PATCH
###############################################################################
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/curl -F auid>=1000 -F auid!=4294967295 -k http_exec_curl
-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/curl -F auid>=1000 -F auid!=4294967295 -k http_exec_curl
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/wget -F auid>=1000 -F auid!=4294967295 -k http_exec_wget
-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/wget -F auid>=1000 -F auid!=4294967295 -k http_exec_wget

###############################################################################
# B) SEND SIZE: flag large network sends from curl/wget (exfil indicator)
#    - sendto/sendmsg a2 = length (bytes). Trigger when >= 100 KB (tune as needed)
###############################################################################
-a always,exit -F arch=b64 -S sendto,sendmsg -F comm=curl -F a2>=100000 -F auid>=1000 -F auid!=4294967295 -k http_large_send_curl
-a always,exit -F arch=b32 -S sendto,sendmsg -F comm=curl -F a2>=100000 -F auid>=1000 -F auid!=4294967295 -k http_large_send_curl
-a always,exit -F arch=b64 -S sendto,sendmsg -F comm=wget -F a2>=100000 -F auid>=1000 -F auid!=4294967295 -k http_large_send_wget
-a always,exit -F arch=b32 -S sendto,sendmsg -F comm=wget -F a2>=100000 -F auid>=1000 -F auid!=4294967295 -k http_large_send_wget

# Optional: stricter “very large” threshold (≈1 MB) for higher confidence
-a always,exit -F arch=b64 -S sendto,sendmsg -F comm=curl -F a2>=1048576 -F auid>=1000 -F auid!=4294967295 -k http_very_large_send_curl
-a always,exit -F arch=b64 -S sendto,sendmsg -F comm=wget -F a2>=1048576 -F auid>=1000 -F auid!=4294967295 -k http_very_large_send_wget
```

**Why these work**

- EXECVE rules gather full ```EXECVE``` and ```PROCTITLE``` records whenever ```curl```/```wget``` run. Those records include the exact command line (e.g., ```-X PUT```, ```--request PROPFIND```, ```--upload-file```, ```-F```, ```--data-binary```), which your SIEM (or a tiny audisp filter) can match to flag uncommon verbs and upload semantics.

- sendto/sendmsg rules watch actual socket send syscalls by ```curl/wget``` and trip when the length (```a2```) exceeds a threshold (e.g., ```>=100000``` ≈ 100 KB or ```>=1048576``` ≈ 1 MB). This is a strong, protocol-agnostic signal for bulk exfil. It will also catch large ```PUT```/```POST``` bodies, regardless of headers.

**Notes**

- ```auid>=1000``` focuses on human accounts; ```4294967295``` (= ```-1```) excludes unset auid. Adjust for your distro if needed.
- We include both b64 and b32 arch rules for completeness.
- These rules are tool-scoped (```comm=curl|wget```) to keep overhead low. Expand to other upload tools in your environment if needed (e.g., ```python3```, ```aws```, ```az```, ```gsutil```) using the same pattern.

**Load / reload rules**
```bash
sudo augenrules --load
# or:
# sudo service auditd restart
```


**How to alert on uncommon verbs - SIEM/Lake search (simple & robust)**

Forward ```linux:audit``` logs to your SIEM and alert when an ```http_exec_*``` event contains rare verbs:

- Match patterns (case-insensitive) in ```EXECVE/PROCTITLE```:

  -    ```--request PUT|PATCH|PROPFIND|PROPPATCH|MKCOL|REPORT|SEARCH|COPY|MOVE|TRACE```

  - ```-X\s*(PUT|PATCH|PROPFIND|PROPPATCH|MKCOL|REPORT|SEARCH|COPY|MOVE|TRACE)```

  - ```Upload hints: --upload-file```, ```-T```, ```-F```, ```--data-binary```, ```--form```, ```-d @```, ```--form-string```, ```filename=```

Example quick check on the box:
```bash
# See recent curl/wget execs and their args:
sudo ausearch -k http_exec_curl -i --start recent | egrep -i 'EXECVE|PROCTITLE' -n
sudo ausearch -k http_exec_wget -i --start recent | egrep -i 'EXECVE|PROCTITLE' -n
```
# How to test (offline-safe)
**Prep: a local HTTP server that accepts POST/PUT and weird verbs**
```bash
cat > /tmp/post_server.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
  def _ok(self): self.send_response(200); self.end_headers(); self.wfile.write(b'OK')
  def do_POST(self): self.rfile.read(int(self.headers.get('Content-Length','0'))); self._ok()
  def do_PUT(self):  self.rfile.read(int(self.headers.get('Content-Length','0'))); self._ok()
  def do_PATCH(self): self.rfile.read(int(self.headers.get('Content-Length','0'))); self._ok()
  def do_PROPFIND(self): self._ok()
  def do_PROPPATCH(self): self._ok()
  def do_MKCOL(self): self._ok()
  def do_REPORT(self): self._ok()
  def do_SEARCH(self): self._ok()
  def do_TRACE(self): self._ok()
HTTPServer(("127.0.0.1", 8088), H).serve_forever()
PY
python3 /tmp/post_server.py
```
**Fire uncommon verb cases (verify EXECVE capture)**
```bash
# PUT upload (also generates large send if file is big)
dd if=/dev/zero of=/tmp/small.bin bs=1K count=20 status=none
curl -X PUT --data-binary @/tmp/small.bin http://127.0.0.1:8088/put

# PATCH with small body
curl -X PATCH -d 'x=1' http://127.0.0.1:8088/patch

# WebDAV-ish verb
curl -X PROPFIND http://127.0.0.1:8088/
```
Check the exec events and confirm the verbs are in EXECVE/PROCTITLE:
```bash
sudo ausearch -k http_exec_curl -i --start recent | egrep -i 'EXECVE|PROCTITLE|-X|--request|PUT|PATCH|PROPFIND'
```
In your SIEM, alert when those patterns appear in events keyed ```http_exec_curl```/```http_exec_wget```.

**Fire large POST (verify send length threshold)**
```bash
# ~2 MB blob
dd if=/dev/zero of=/tmp/big.bin bs=1M count=2 status=none

# Large POST body (Content-Length ~ 2,097,152)
curl -X POST --data-binary @/tmp/big.bin http://127.0.0.1:8088/upload
```
Look for matching sendto/sendmsg events with ```a2``` >= threshold:
```bash
# 100 KB threshold hits:
sudo ausearch -k http_large_send_curl --start recent | aureport -au --summary 2>/dev/null || true

# Raw look to inspect a2 (length) and syscall names:
sudo ausearch -k http_large_send_curl --start recent -i | egrep -i 'syscall=|a2=| comm=| exe=' -n
# or broader:
sudo ausearch -k http_very_large_send_curl --start recent -i
```
You should see audit records for ```sendto```/```sendmsg``` from ```comm="curl"``` where ```a2``` (length) is ~2,097,152.

**Test with wget (both exec & large send)**
```bash
wget --method=PUT --body-file=/tmp/small.bin http://127.0.0.1:8088/wput -O /dev/null
wget --method=POST --body-file=/tmp/big.bin  http://127.0.0.1:8088/wpost -O /dev/null

sudo ausearch -k http_exec_wget -i --start recent | egrep -i 'EXECVE|PROCTITLE|--method|PUT|POST'
sudo ausearch -k http_large_send_wget -i --start recent
```
# Tuning tips

- Thresholds: Start with ```a2>=1048576``` (1 MB) for high-confidence large sends; add the 100 KB rule if you want earlier warning.

- Scope: If you want broader coverage beyond curl/wget, add similar ```sendto/sendmsg``` rules for ```python3```, ```node```, ```java```, backup or RMM agents, etc.—but expect more noise.

- Noise management: If dev workflows legitimately push large payloads, allow-list by user (```auid```), path (```exe```), or time ranges.

- Overhead: These rules are narrow and low-overhead on modern hosts. Avoid monitoring all ```sendto``` without ```comm``` scoping.

