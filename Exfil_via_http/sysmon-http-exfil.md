# Sysmon for Linux rules: exfiltration via uncommon HTTP verbs and large POST–style uploads driven by curl/wget
**Sysmon for Linux rules (drop-in XML)**
Save this as ```sysmon-http-exfil.xml```.(a version of this sysmon-http-exfil.xml is available on this github) You can use it as your whole config or merge the ```<EventFiltering>``` blocks into your existing one.
Tune verb lists and heuristics to your environment.
```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>

    <!-- ===========================================================
         1) PROCESS CREATE (Event ID 1)
         Primary signal: detect curl/wget invoked with:
           - uncommon/“write-like” HTTP verbs (PUT, PATCH, WebDAV)
           - upload flags (data-binary @file, post-file/body-file, multipart form)
         =========================================================== -->
    <ProcessCreate onmatch="include">

      <!-- curl + uncommon verb + evidence of a request body -->
      <RuleGroup name="Curl_UncommonVerb_WithBody" groupRelation="and">
        <Image condition="end with">/curl</Image>
        <!-- Uncommon/administrative verbs -->
        <CommandLine condition="contains any">-X PUT|--request PUT|-X PATCH|--request PATCH|-X PROPFIND|--request PROPFIND|-X PROPPATCH|--request PROPPATCH|-X MKCOL|--request MKCOL|-X REPORT|--request REPORT|-X SEARCH|--request SEARCH|-X COPY|--request COPY|-X MOVE|--request MOVE|-X TRACE|--request TRACE</CommandLine>
        <!-- Signs there is a body being sent -->
        <CommandLine condition="contains any">--data-binary|--data|-d |--upload-file|-T|-F|--form</CommandLine>
      </RuleGroup>

      <!-- wget + uncommon verb + evidence of a request body -->
      <RuleGroup name="Wget_UncommonVerb_WithBody" groupRelation="and">
        <Image condition="end with">/wget</Image>
        <CommandLine condition="contains any">--method=PUT|--method=PATCH|--method=PROPFIND|--method=PROPPATCH|--method=MKCOL|--method=REPORT|--method=SEARCH|--method=COPY|--method=MOVE|--method=TRACE</CommandLine>
        <!-- Wget upload indicators -->
        <CommandLine condition="contains any">--body-file=|--post-file=|--header=Content-Length|--header=Transfer-Encoding: chunked</CommandLine>
      </RuleGroup>

      <!-- curl heuristic for large/binary POST-like transfers -->
      <RuleGroup name="Curl_LargePOST_Heuristic" groupRelation="and">
        <Image condition="end with">/curl</Image>
        <!-- Explicit file upload flags -->
        <CommandLine condition="contains any">--data-binary @|-d @|--upload-file|-T</CommandLine>
        <!-- Optional: “binary-ish” content type often used during bulk uploads -->
        <CommandLine condition="contains any">application/octet-stream</CommandLine>
      </RuleGroup>

      <!-- wget heuristic for large/binary POST-like transfers -->
      <RuleGroup name="Wget_LargePOST_Heuristic" groupRelation="and">
        <Image condition="end with">/wget</Image>
        <CommandLine condition="contains any">--body-file=|--post-file=</CommandLine>
      </RuleGroup>

      <!-- curl multipart form upload (file=@path) -->
      <RuleGroup name="Curl_MultipartUpload" groupRelation="and">
        <Image condition="end with">/curl</Image>
        <CommandLine condition="contains">-F</CommandLine>
        <CommandLine condition="contains">@</CommandLine>
      </RuleGroup>
    </ProcessCreate>

    <!-- ===========================================================
         2) NETWORK CONNECT (Event ID 3) — Context signal
         Connections initiated by curl/wget (helps triage/sequence the action).
         =========================================================== -->
    <NetworkConnect onmatch="include">
      <RuleGroup name="Curl_Egress" groupRelation="and">
        <Image condition="end with">/curl</Image>
        <Initiated condition="is">true</Initiated>
      </RuleGroup>
      <RuleGroup name="Wget_Egress" groupRelation="and">
        <Image condition="end with">/wget</Image>
        <Initiated condition="is">true</Initiated>
      </RuleGroup>
    </NetworkConnect>

  </EventFiltering>
</Sysmon>
```
**Why these rules work**
- ProcessCreate (EID 1) gives you the full ```CommandLine```. Exfil via HTTP often uses:

  -  Uncommon / write-like verbs (e.g., ```PUT```, ```PATCH```, WebDAV verbs). These are rare in most enterprise traffic and strongly imply upload semantics.

  - Explicit upload flags:

    - ```curl```: ```--data-binary @file```, ```-d @file```, ```--upload-file```, ```-T```, ```-F/--form file=@…```

    - ```wget```: ```--body-file=```, ```--post-file=```, ```--method=PUT```
      <br>Matching these strings is a high-signal indicator the process is sending data to a remote HTTP server.

- **NetworkConnect (EID 3)** confirms the egress connection came from ```curl```/```wget```, aiding timeline building and suppression of edge cases (e.g., someone builds a curl command but never executes it).

Note: Sysmon (Linux/Windows) doesn’t expose HTTP header/body sizes, so “large POST” is detected heuristically via upload flags and content-type hints (the tools and modes most often used to push large blobs).

# Implementation steps
**1. Install/verify Sysmon for Linux**

- Official packages are available from Microsoft’s Sysinternals. (Assumes you already have it installed as a service.)

**2. Back up existing config**
```bash
sudo cp /etc/sysmon/sysmon.xml /etc/sysmon/sysmon.xml.bak 2>/dev/null || true
```
**3. Deploy the rules**
```bash
sudo tee /etc/sysmon/sysmon-http-exfil.xml >/dev/null <<'XML'
# (paste the XML from above here)
XML

# Load (replace running config with the new file)
sudo sysmon -c /etc/sysmon/sysmon-http-exfil.xml
```
**4. Confirm it's active**
```bash
sudo systemctl status sysmon 2>/dev/null || ps aux | grep -i sysmon
# See recent events (tag often "sysmon")
journalctl -t sysmon -S "2 minutes ago" | tail -n +1
```
**5. Forward events to your SIEM (recommended) and alert on the RuleGroup names or the CommandLine patterns you care about.**

# How to test (offline, reproducible)

**Spin up a tiny local HTTP server that accepts POST/PUT/PATCH/WebDAV-ish verbs and then fire curl/wget commands that trip the rules.**

**0) Start a permissive local HTTP server
```bash
cat > /tmp/post_server.py <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
  def _ok(self): self.send_response(200); self.end_headers(); self.wfile.write(b'OK')
  def _read(self): self.rfile.read(int(self.headers.get('Content-Length','0')))
  def do_POST(self): self._read(); self._ok()
  def do_PUT(self):  self._read(); self._ok()
  def do_PATCH(self): self._read(); self._ok()
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

**A) Uncommon verb with body (fires Curl/Wget_UncommonVerb_WithBody)**
```bash
# Small test payload
dd if=/dev/zero of=/tmp/small.bin bs=1K count=20 status=none

# curl (PUT) – uncommon verb + body
curl -X PUT --data-binary @/tmp/small.bin http://127.0.0.1:8088/put

# wget (PUT) – uncommon verb + body-file
wget --method=PUT --body-file=/tmp/small.bin http://127.0.0.1:8088/wput -O /dev/null
```
**Check events**\
```bash
journalctl -t sysmon -S "5 minutes ago" | egrep -i "EventID=1|Process Create|curl|wget|PUT|PROPFIND|PATCH|body-file|data-binary|upload-file"
```
You should see **EventID=1** with ```Image=/.../curl``` (or ```/.../wget```) and the ```CommandLine``` containing the uncommon verb and a body flag.

**B) “Large POST” heuristics (fires Curl/Wget_LargePOST_Heuristic)**
```bash
# ~2 MB payload
dd if=/dev/zero of=/tmp/big.bin bs=1M count=2 status=none

# curl binary upload (Content-Type hint helps)
curl -H "Content-Type: application/octet-stream" --data-binary @/tmp/big.bin http://127.0.0.1:8088/upload

# wget large POST from file
wget --method=POST --body-file=/tmp/big.bin http://127.0.0.1:8088/wpost -O /dev/null
```
**Check events**
```bash
journalctl -t sysmon -S "5 minutes ago" | egrep -i "EventID=1|curl.*data-binary @|wget.*(post-file|body-file)|application/octet-stream"
```
**C) Multipart upload (fires Curl_MultipartUpload)**
```bash
curl -F "file=@/etc/hosts" http://127.0.0.1:8088/form
journalctl -t sysmon -S "5 minutes ago" | egrep -i "EventID=1|curl| -F |@/etc/hosts"
```
**D) Network connect context (fires Curl/Wget_Egress)**

**Any of the above will also create EventID=3 from the same ```Image```:**
```bash
journalctl -t sysmon -S "5 minutes ago" | egrep -i "EventID=3|Network connection|/curl|/wget"
```
# Tuning tips
- Reduce noise: If devs legitimately use multipart or PUT, add an exclude block before the include rules to allow-list known hosts or wrapper scripts.
```xml
<ProcessCreate onmatch="exclude">
  <CommandLine condition="contains any">api.mycompany.com|artifacts.company</CommandLine>
</ProcessCreate>
```
- Beyond curl/wget: Extend to other tools your users employ for uploads (```python3```, ```java```, ```aws```, ```az```, ```gsutil```, ```rclone```)—match their upload flags similarly.

- Correlate: Pair with Suricata’s HTTP rules and auditd ```sendto/sendmsg``` size thresholds to get both intent (command line) and volume (bytes sent).