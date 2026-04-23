# Worksheet answers — DNS tunneling exercise

## Observed Indicators

### Which characteristics in the PCAP indicate DNS tunneling?

The PCAP shows a large number of DNS queries to one repeated parent domain, `tunnel.lab`. The left-most subdomain labels are unusually long and random-looking, for example Base32-style strings using letters and digits such as `a-z` and `2-7`. Many queries contain unique subdomains while the suffix remains constant, which is typical when data is encoded into DNS query names. The query frequency is also higher than normal human web browsing DNS activity, and the answers use very low TTL values. These patterns indicate that DNS is being used as a data transport channel rather than only for normal name resolution.

## Detection Approach

### Which IDS tool and rule were used?

Suricata was used with the local rule file `rules/suricata_dns_tunnel.rules`. Two lab rules were used. The first rule detects DNS queries containing the known tunnel suffix `.tunnel.lab`. The second rule is a heuristic PCRE rule that detects long Base32-like DNS labels followed by a sequence label, a session label, and the `tunnel.lab` suffix.

Example Suricata command:

```bash
suricata -r pcaps/demo_dns_tunnel.pcap -S rules/suricata_dns_tunnel.rules -l reports/suricata -k none
```

Main Suricata rules:

```text
alert dns any any -> any any (msg:"LAB DNS tunneling domain tunnel.lab"; dns.query; content:".tunnel.lab"; nocase; sid:1000001; rev:1; classtype:policy-violation;)
alert dns any any -> any any (msg:"LAB Possible DNS tunnel long encoded label"; dns.query; pcre:"/[a-z2-7]{45,}\.[0-9]{3}\.[a-z0-9]{6}\.tunnel\.lab$/i"; sid:1000002; rev:1; classtype:policy-violation;)
```

## Which DNS patterns triggered the detection?

The detection triggered on DNS queries ending in `.tunnel.lab` and on long encoded labels before that suffix. The suspicious labels were around 45 characters or longer, contained high-entropy Base32-like text, and appeared repeatedly with changing subdomains. Repeated use of the same tunnel suffix combined with unique, long subdomains was the strongest pattern.

## Limitations and Evasion

### Which weaknesses does your detection approach have?

The domain-based rule is reliable only when the tunnel domain is already known. It will miss a tunnel that uses a different domain. The long-label heuristic can also create false positives for legitimate services that use long encoded DNS names, such as some CDN, tracking, anti-abuse, or verification systems. It may miss tunnels that use shorter chunks, lower frequency, or more natural-looking labels. The rule also does not reconstruct payloads or prove intent; it only identifies suspicious DNS behavior.

### How could an attacker modify the tunnel to evade detection?

An attacker could reduce the query rate, use shorter encoded chunks, rotate domains, add random delays, or use labels that look more like normal hostnames. They could also spread traffic across several domains or use DNS record types such as TXT, NULL, or CNAME depending on the environment. More advanced evasion could use padding, compression, encryption, or domain fronting-style infrastructure. These changes would make simple domain and long-label signatures less effective, so defenders should combine signatures with behavioral detection, baselines, entropy checks, query-volume monitoring, and DNS egress controls.
