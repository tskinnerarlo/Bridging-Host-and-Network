# Bridging-Host-and-Network
# Title: Bridging Host and Network: Enriching Linux Shell Abuse Detection with Suricata
Threat Detection Engineering / Network Security / Host-Network Correlation

Abstract:

As attackers increasingly weaponize native Linux tools (e.g., bash, curl, wget, nc) to perform file-less intrusions and establish persistence, defenders must bridge the gap between host-based monitoring and network detection to build context-rich detections.

This talk presents a novel approach to real-time detection of Linux shell abuse using a blended strategy of host-based telemetry from auditd and Sysmon for Linux with enriched network signals from Suricata. The presentation walks through the lifecycle of a typical shell-based attack, shows how it manifests in both host and network layers, and demonstrates how to correlate events using Suricata EVE logs alongside host audit data.

We will introduce custom Suricata rules that detect:

Reverse shell setup (e.g., nc, bash -i traffic)

File downloads from suspicious TLDs via curl or wget

Exfiltration via uncommon HTTP verbs or large POSTs

TLS JA3 hashes associated with post-exploitation tools

Each detection is paired with a corresponding auditd or Sysmon event, creating a high-confidence, low-noise alert model. All examples will be open source and reproducible.
