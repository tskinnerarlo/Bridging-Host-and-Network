# Exfiltration via uncommon HTTP verbs (WebDAV/PUT/PATCH/etc.)

**Save these into a file like http_exfil.rules and include it in suricata.yaml (rule-files:).
Tune method lists, size thresholds, and netvars ($HOME_NET, $EXTERNAL_NET) for your environment.**

```bash
###############################################################################
# Exfiltration via uncommon HTTP verbs (WebDAV/PUT/PATCH/etc.)
###############################################################################

# 200101 — Uncommon HTTP methods that often imply upload/write behavior
# this rule still needs some work, not really catching the methods when sent with curl -X for testing
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"HTTP exfil: uncommon method with body (PUT/PATCH/PROPFIND/PROPPATCH/MKCOL/REPORT/SEARCH/TRACE/COPY/MOVE)";
    flow:established,to_server;
    http.method; pcre:"/^(?:PUT|PATCH|PROPFIND|PROPPATCH|MKCOL|REPORT|SEARCH|TRACE|COPY|MOVE)$/";
    http.header; content:"Content-Length:"; nocase;            # indicates a request body
    classtype:data-loss;
    metadata: created_at 2025_08_29, attack_target Server, mitre_technique_id T1041, mitre_technique_name "Exfiltration Over C2 Channel", mitre_technique_id T1567, mitre_technique_name "Exfiltration to Cloud Storage";
    threshold:type limit, track by_src, count 1, seconds 60;
    sid:200101; rev:1;
)

###############################################################################
# Exfiltration via large POST bodies
###############################################################################

# 200102 — Large POST (>= ~1MB) by Content-Length (fast, header-only)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"HTTP exfil: large POST body (>= ~1MB)";
    flow:established,to_server;
    http.method; content:"POST";
    # Match Content-Length with 7+ digits => >=1,000,000 bytes (approx >=1MB).
    # ^ and /m allow anchoring to the header line start.
    http.header; pcre:"/^\s*Content-Length:\s*(?:[1-9]\d{6,})/Hmi";
    classtype:data-loss;
    metadata: created_at 2025_08_29, attack_target Server, note "Header-based size check";
    threshold:type both, track by_src, count 1, seconds 120;
    sid:200102; rev:1;
)

# 200103 — File upload via multipart/form-data (POST with filename=)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"HTTP exfil: POST multipart file upload (filename=)";
    flow:established,to_server;
    http.method; content:"POST";
    http.header; content:"Content-Type:"; nocase;
    http.header; content:"multipart/form-data"; nocase;
    http.request_body; content:"filename="; nocase;
    classtype:data-loss;
    metadata: created_at 2025_08_29, attack_target Server, note "Multipart upload with filename field";
    threshold:type limit, track by_src, count 2, seconds 120;
    sid:200103; rev:1;
)

# 200104 — Bulk binary POST (octet-stream) with large body (~>=100 KB)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"HTTP exfil: POST application/octet-stream (>= ~100KB)";
    flow:established,to_server;
    http.method; content:"POST";
    http.header; content:"Content-Type:"; nocase;
    http.header; content:"application/octet-stream"; nocase;
    # 6+ digits => >=100,000 bytes (roughly 100KB)
    http.header; pcre:"/^\s*Content-Length:\s*(?:[1-9]\d{5,})/Hmi";
    classtype:data-loss;
    metadata: created_at 2025_08_29, attack_target Server, note "Binary payload upload";
    threshold:type both, track by_src, count 1, seconds 120;
    sid:200104; rev:1;
)
```
**Notes**
- **Uncommon verbs** include WebDAV methods; most orgs don’t use them outside dev/admin flows. Requiring a request body via ```Content-Length:``` makes these alerts higher-signal for exfil attempts (i.e., upload/write).
- For “large POST,” we use a **header-only** numeric heuristic. Suricata rules can’t do numeric math directly on header values, but a regex for digit count is a solid approximation (≥7 digits ≈ ≥1MB; ≥6 digits ≈ ≥100KB).
- ```http.request_body; content:"filename="``` positively identifies multipart file uploads (common for exfil to web services).
- Add allow-lists (e.g., ```http.host; content:"api.mycompany.com";``` in an exclude rule) to reduce noise from known business apps.

**Why these work**

- Exfil often uses methods that imply upload: ```PUT```, ```PATCH```, or WebDAV verbs (e.g., ```PROPPATCH```, ```MKCOL```) are unusual in most environments and commonly correlate with write operations to remote servers. Checking for a body (```Content-Length```) catches when data is being pushed.

- Large POSTs are a classic signature of bulk data leaving the host (e.g., db dumps, archives). Header-based size checks are cheap and work regardless of TLS; you’re inspecting the request from the client → server side before encryption on some sensors or after decryption on proxies (depending on placement).

- **Multipart with** ```filename=``` is a strong indicator of a file upload via HTML forms or programmatic clients.

**Make sure HTTP bodies are inspected**

In suricata.yaml, confirm/request-body inspection is enabled and not too small:
```yaml
app-layer:
  protocols:
    http:
      enabled: yes
      request-body: yes
      response-body: no

# In the libhtp section (names vary by version):
libhtp:
  default-config:
    request-body-limit: 0         # 0 = unlimited (or set >= size you care about, e.g., 10485760 for 10MB)
    request-body-minimal-inspect-size: 32768
    request-body-inspect-window: 4096
```
(If the request-body is truncated below your thresholds, the multipart rule still works, but the large POST rule relies on headers—so it will still fire.)

## How to test (offline-safe)
**0) Minimal local HTTP receiver (accepts POST, PUT, weird verbs)**

Use Python’s stdlib:
```bash
cat > /tmp/post_server.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def _ok(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'OK')
    def do_POST(self): self.rfile.read(int(self.headers.get('Content-Length','0'))); self._ok()
    def do_PUT(self):  self.rfile.read(int(self.headers.get('Content-Length','0'))); self._ok()
    def do_PATCH(self): self.rfile.read(int(self.headers.get('Content-Length','0'))); self._ok()
    def do_PROPFIND(self): self._ok()
    def do_PROPPATCH(self): self._ok()
    def do_MKCOL(self): self._ok()
    def do_REPORT(self): self._ok()
    def do_SEARCH(self): self._ok()
    def do_TRACE(self): self._ok()
HTTPServer(("0.0.0.0", 8088), H).serve_forever()
PY
python3 /tmp/post_server.py
```
Run Suricata on the interface that sees this traffic (e.g., lo for local tests), with your new http_exfil.rules loaded.

**A) Fire the uncommon verb rule (sid:200101)**
```bash
# Any of these will do (each should trigger 200101):
curl -X PROPFIND http://127.0.0.1:8088/
curl -X PATCH -d 'x=1' http://127.0.0.1:8088/patch
curl -X PUT --data-binary @/etc/hosts http://127.0.0.1:8088/put
```

**Check alerts:**
```bash
jq 'select(.alert and .alert.signature_id==200101) | {ts: .timestamp, src:.src_ip, dst:.dest_ip, sig:.alert.signature}' \
  /var/log/suricata/eve.json
```

**B) Fire the large POST (~≥1MB) rule (sid:200102)**
```bash
# Create a ~2MB blob
dd if=/dev/zero of=/tmp/big.bin bs=1M count=2 status=none

# Send it (Content-Length will be ~2,097,152)
curl -X POST --data-binary @/tmp/big.bin http://127.0.0.1:8088/upload
```
**Verfy:**
```bash
jq 'select(.alert and .alert.signature_id==200102) | {ts:.timestamp, len:(.http.http_request_headers[]? | select(.name=="Content-Length") | .value), sig:.alert.signature}' \
  /var/log/suricata/eve.json
```
**C) Fire the multipart filename= rule (sid:200103)**
```bash
# Multipart POST with a real filename field
curl -F "file=@/etc/hosts" http://127.0.0.1:8088/form
```
**Verfy:**
```bash
jq 'select(.alert and .alert.signature_id==200103) | {ts:.timestamp, sig:.alert.signature}' /var/log/suricata/eve.json
```
D) Fire the octet-stream 100KB+ rule (sid:200104)
```bash
dd if=/dev/urandom of=/tmp/100k.bin bs=100K count=1 status=none
curl -X POST -H "Content-Type: application/octet-stream" --data-binary @/tmp/100k.bin http://127.0.0.1:8088/bulk
```
**Verfy:**
```bash
jq 'select(.alert and .alert.signature_id==200104) | {ts:.timestamp, sig:.alert.signature}' /var/log/suricata/eve.json
```

## Tuning & hardening tips
- Allow-lists: Prepend an exclude rule group for known-good hosts or paths (backup agents, artifact repos) to suppress noise.

- Thresholding: Already included to reduce alert storms. Adjust ```seconds```/```count``` to fit traffic volume.

- Chunked uploads: If your environment uses ```Transfer-Encoding: chunked```, header size isn’t present. Consider flagging ```POST``` + ```Transfer-Encoding: chunked``` + ```multipart/form-data``` as a medium-confidence signal.

- Placement: You’ll see the most with sensors closest to the clients (before proxy/TLS) or after TLS interception on egress proxies.

- Correlate with DNS, proxy logs, and host EDR (who launched curl? what data left?).
