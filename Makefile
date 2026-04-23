PYTHON ?= python3

.PHONY: install demo-pcap analyze clean

install:
	$(PYTHON) -m pip install -r requirements.txt

demo-pcap:
	$(PYTHON) src/generate_demo_pcap.py --output pcaps/demo_dns_tunnel.pcap

analyze: demo-pcap
	$(PYTHON) src/analyze_pcap.py pcaps/demo_dns_tunnel.pcap --domain tunnel.lab

clean:
	rm -f pcaps/*.pcap reports/*.log reports/*.txt
