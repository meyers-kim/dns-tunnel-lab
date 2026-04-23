# Exercise 04 — DNS tunneling lab with Wireshark, PCAP analysis, and IDS rules

This package is a **safe localhost lab** for the DNS tunneling exercise. It creates DNS tunnel-like traffic under `tunnel.lab`, captures or generates a PCAP, analyzes the indicators, and provides Suricata/Snort rules.

The included Python client/server do not create an internet-facing covert channel. By default, the server binds to `127.0.0.1:5353` only. This is intended for your own VM/lab environment.

## Contents

```text
src/dns_tunnel_server.py       Local DNS server that decodes Base32 labels
src/dns_tunnel_client.py       Client that sends messages via DNS query names
src/generate_demo_pcap.py      Creates pcaps/demo_dns_tunnel.pcap without root privileges or Scapy
src/analyze_pcap.py            Finds DNS tunneling indicators in a PCAP
rules/suricata_dns_tunnel.rules
rules/snort_dns_tunnel.rules
examples/payload.txt
requirements.txt
Makefile
```

## 1. Install

Use Linux or a cybersecurity VM with Python 3.10+.

```bash
unzip dns_tunnel_lab.zip
cd dns_tunnel_lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional tools for the exercise:

```bash
sudo apt update
sudo apt install wireshark tcpdump suricata snort
```

## 2. Establish the DNS communication channel

Terminal 1 — start the local DNS server:

```bash
python3 src/dns_tunnel_server.py --host 127.0.0.1 --port 5353 --domain tunnel.lab
```

Terminal 2 — send a ping-like message through DNS:

```bash
python3 src/dns_tunnel_client.py --server 127.0.0.1 --port 5353 --message "ping: hello through DNS"
```

Send HTTP-like data:

```bash
python3 src/dns_tunnel_client.py --server 127.0.0.1 --port 5353 --message "GET /index.html HTTP/1.1 Host: example.local"
```

Send a small file as encoded DNS labels:

```bash
python3 src/dns_tunnel_client.py --server 127.0.0.1 --port 5353 --file examples/payload.txt --repeat 5 --delay 0.05
```

Verify the server prints decoded content and writes it to:

```text
reports/server-decoded.log
```

## 3. Capture DNS traffic

With tcpdump on Linux loopback:

```bash
sudo tcpdump -i lo -w pcaps/live_dns_tunnel.pcap udp port 5353
```

While tcpdump is running, generate traffic in another terminal:

```bash
python3 src/dns_tunnel_client.py --server 127.0.0.1 --port 5353 --file examples/payload.txt --repeat 20 --delay 0.02
```

Stop tcpdump with `Ctrl+C`. Open the file in Wireshark:

```bash
wireshark pcaps/live_dns_tunnel.pcap
```

Useful Wireshark filters:

```text
udp.port == 5353
dns
dns.qry.name contains "tunnel.lab"
frame contains "tunnel"
```

If loopback capture is inconvenient, generate a ready-made PCAP without root privileges:

```bash
python3 src/generate_demo_pcap.py --output pcaps/demo_dns_tunnel.pcap
```

## 4. Analyze the PCAP

```bash
python3 src/analyze_pcap.py pcaps/demo_dns_tunnel.pcap --domain tunnel.lab
```

Expected indicators:

- Many DNS queries to the same suffix: `tunnel.lab`
- Long labels, often around 45–50 characters
- Random/Base32-looking characters such as `a-z` and `2-7`
- High query frequency compared with normal DNS browsing
- Very low TTL in responses
- Unique subdomains with repeated parent domain/session labels

## 5. IDS detection with Suricata

Run Suricata against the generated PCAP:

```bash
mkdir -p reports/suricata
suricata -r pcaps/demo_dns_tunnel.pcap -S rules/suricata_dns_tunnel.rules -l reports/suricata -k none
cat reports/suricata/fast.log
```

The rules should trigger on:

- The known tunnel domain suffix `.tunnel.lab`
- Long Base32-like encoded labels before `.tunnel.lab`

## 6. IDS detection with Snort

Snort installations vary. A common pattern is:

```bash
snort -A console -q -r pcaps/demo_dns_tunnel.pcap -c /etc/snort/snort.conf -R rules/snort_dns_tunnel.rules
```

On my Snort version, the -R option did not work because it was interpreted as a pidfile suffix. 
I copied the  Snort rules to reports/snort/local.rules and replaced the unsupported classtype with priority:1. 
Then I ran Snort with a small local config and a local log directory.

```bash
mkdir -p reports/snort/logs

sed 's/classtype:policy-violation;/priority:1;/g' \
  rules/snort_dns_tunnel.rules > reports/snort/local.rules

cat > reports/snort/snort-lab.conf <<'EOF'
var HOME_NET any
var EXTERNAL_NET any
var RULE_PATH ./reports/snort

config checksum_mode: none

include $RULE_PATH/local.rules
EOF

snort -A console -q \
  -r pcaps/demo_dns_tunnel.pcap \
  -c reports/snort/snort-lab.conf \
  -k none \
  -l reports/snort/logs
```

