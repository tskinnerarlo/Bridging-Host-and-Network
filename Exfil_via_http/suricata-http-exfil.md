# Exfiltration via uncommon HTTP verbs (WebDAV/PUT/PATCH/etc.)

**Save these into a file like http_exfil.rules and include it in suricata.yaml (rule-files:).
Tune method lists, size thresholds, and netvars ($HOME_NET, $EXTERNAL_NET) for your environment.**

```bash
###############################################################################
# Exfiltration via uncommon HTTP verbs (WebDAV/PUT/PATCH/etc.)
###############################################################################

# 200101 — Uncommon HTTP methods that often imply upload/write behavior
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