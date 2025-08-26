In Suricata rule syntax, "keeping the checks in separate sticky buffers" refers to an important behavior change in modern Suricata (version 7.0 and later), specifically for how it handles multiple instances of the same sticky buffer within a single transaction. Instead of applying subsequent checks to the same buffer instance, Suricata creates a separate, new buffer for each sticky buffer keyword. [1, 2]

This allows for more precise and efficient rule-writing, especially for protocols that can have multiple instances of the same element in a single session, such as DNS queries with multiple question records or HTTP/2 transactions with multiple headers. [3, 4, 5, 6]

***How sticky buffers work***

A sticky buffer is a rule keyword that "sticks" the focus of subsequent payload-related keywords (like or ) to a specific part of a network packet or application-layer data. [7]

***Before Suricata 7.0:***

- A single instance of a sticky buffer applied to all subsequent payload checks.
- For example, a rule with ```dns.query; content:"example", content:".com";``` would only match on a DNS query containing the full string "example.com" or "example.something.com". It would not match if the same DNS transaction contained two separate queries, such as one for "example.net" and another for "something.com". [2, 4, 5]

***Suricata 7.0 and later ("separate sticky buffers"):***

- Each ```dns.query``` keyword starts a new, separate sticky buffer instance for that query.

- Now, a rule with ```dns.query; content:"example"; dns.query; content:".com";``` can correctly fire if two separate query records within the same DNS transaction contain "example" and ".com" respectively. [1]

Example: Matching on multiple DNS queries
Consider the following rule, which is much more robust with the modern "separate sticky buffers" behavior:

```alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"DNS Multiple Query Example"; dns.query; content:"example"; dns.query; content:".com"; classtype:misc-activity; sid:1; rev:1;)```


- Older behavior (pre-7.0): This rule could only match on a single DNS query containing both "example" and ".com" (e.g., ```example.com``` ). The second dns.query keyword was effectively ignored.
- Modern behavior (7.0+): This rule now works as intended. Suricata creates a separate sticky buffer for each keyword. It will alert if it finds a DNS transaction that contains one query with the string "example" and another query with the string ".com". [1, 2]

***Benefits of separating sticky buffers***
This design improves Suricata's rule-writing capabilities in several key ways:

- Improved accuracy: It reduces false negatives by enabling more precise matching for protocols that contain repeating elements in a single transaction.
- Support for modern protocols: It allows for better inspection of complex application layers like HTTP/2, where multiple headers can be present.
- Easier rule logic: The syntax more naturally expresses the intent of matching on distinct parts of a conversation, rather than a single contiguous block of data. [1, 4, 8]


[1] https://docs.suricata.io/en/latest/rules/multi-buffer-matching.html<br>
[2] https://docs.suricata.io/en/latest/rules/multi-buffer-matching.html<br>
[3] https://docs.suricata.io/en/latest/rules/mdns-keywords.html<br>
[4] https://docs.suricata.io/en/suricata-7.0.2/rules/multi-buffer-matching.html<br>
[5] https://docs.suricata.io/en/suricata-7.0.2/rules/multi-buffer-matching.html<br>
[6] https://docs.suricata.io/en/latest/rules/multi-buffer-matching.html<br>
[7] https://docs.suricata.io/en/suricata-7.0.3/rules/http-keywords.html<br>
[8] https://gregorykelleher.com/nginx_security<br>
