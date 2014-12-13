firewall
========

Tool for setting up your firewall based on iptables

FILES:
- firewall.sh: main script, need to run
- blacklist.txt: list of bad ips will be blocked (one ip per line)
- whitelist.txt: list of good ips will be accepted (one ip per line)

RUN:
- firewall.sh start: start firewall
- firewall.sh stop: stop firewall
