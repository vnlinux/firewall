firewall
========

Tool for setting up your firewall based on iptables

##Files
- firewall.sh: main script, need to run
- blacklist.txt: list of bad ips will be blocked (one ip per line)
- whitelist.txt: list of good ips will be accepted (one ip per line)

##Usage

Start firewall
```sh
sudo sh firewall.sh start
```
Stop firewall
```sh
sudo sh firewall.sh stop
```
Start firewall, and stop it after 5 minutes (testing mode)
```sh
sudo sh firewall.sh start; (sleep 300; sudo sh firewall.sh stop) &
```
