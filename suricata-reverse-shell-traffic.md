**Here are Suricata rules to detect on the two following criterea:**

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

