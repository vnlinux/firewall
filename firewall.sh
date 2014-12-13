#!/bin/bash

### Declare some system variables
IPT=$(which iptables)
EXT_IF=$(/sbin/ip route | grep default | awk '{print $5}') # external network interface
INT_IF=$(ip link show | grep "state UP" | grep -v $EXT_IF | awk '{print $2}' | cut -d':' -f1) # all internal network interfaces

### Declare some options to choose
LAN_ALLOW="1" # this will set allow all connection from LAN
BLACKLIST_BLOCK="1" # enable block ips from blacklist
WHITELIST_ALLOW="1" # enable allow ips from whitelist

### List incoming and outgoing TCP & UDP ports (22 is mandatory, not list here)
incoming_tcp="80,443"
incoming_udp="53"
outgoing_tcp="22,53"
outgoing_udp="53,123"

### File
black_list="blacklist.txt"
white_list="whitelist.txt"

### Check if file is found
if [ $BLACKLIST_BLOCK = "1" ] && [ ! -f $black_list ]; then
	echo "File $black_list not found."
	exit 1
fi

if [ $WHITELIST_ALLOW = "1" ] && [ ! -f "$white_list" ]; then
	echo "File $white_list not found."
	exit 1
fi

### STARTING FIREWALL
echo "STARTING FIREWALL:"

### Set default chain policies
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT DROP

### Delete all existing rules
echo "-> flush all existing rules"
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

### Allow allow loopback
echo "-> allow loopback"
$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

### Allow LAN connection
if [ "$LAN_ALLOW" = "1" ]; then
	echo "-> allow all LAN connection"
	for eth in $INT_IF; do
		$IPT -A INPUT -i $eth -j ACCEPT
		$IPT -A OUTPUT -o $eth -j ACCEPT
	done
fi

### Allow current established and related connections
echo "-> allow current established connections"
$IPT -A INPUT 	-m state --state RELATED,ESTABLISHED -j ACCEPT 
$IPT -A OUTPUT 	-m state --state RELATED,ESTABLISHED -j ACCEPT 

### Allow incoming SSH
echo "-> allow incoming SSH"
$IPT -A INPUT 	-i $EXT_IF -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT 	-o $EXT_IF -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

### Allow good ip from whitelist file
if [ "$WHITELIST_ALLOW" = "1" ]; then
	echo "-> allow good ips from whitelist"
	$IPT -N acceptlist
	good_ips=$(egrep -v -E "^#|^$" $white_list)
	for ip in $good_ips; do
		$IPT -A acceptlist -s $ip -j ACCEPT
	done
	# insert or append our acceptlist
	$IPT -I INPUT -j acceptlist
	$IPT -I OUTPUT -j acceptlist
	$IPT -I FORWARD -j acceptlist
fi

### Block bad ip from blacklist file
if [ "$BLACKLIST_BLOCK" = "1" ]; then
	echo "-> block bad ips from blacklist"
	$IPT -N droplist
	bad_ips=$(egrep -v -E "^#|^$" $black_list)
	for ip in $bad_ips; do
		$IPT -A droplist -s $ip -j LOG --log-prefix "Drop ip in blacklist"
		$IPT -A droplist -s $ip -j DROP
	done
	# insert or append our droplist 
	$IPT -I INPUT -j droplist
	$IPT -I OUTPUT -j droplist
	$IPT -I FORWARD -j droplist
fi

### Allow incoming TCP
echo "-> allow incoming $incoming_tcp"
$IPT -A INPUT 	-i $EXT_IF -p tcp -m multiport --dports $incoming_tcp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT 	-o $EXT_IF -p tcp -m multiport --sports $incoming_tcp -m state --state ESTABLISHED -j ACCEPT

### Allow incoming UDP
echo "-> allow incoming $incoming_udp"
$IPT -A INPUT 	-i $EXT_IF -p udp -m multiport --dports $incoming_udp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT 	-o $EXT_IF -p udp -m multiport --sports $incoming_udp -m state --state ESTABLISHED -j ACCEPT

### Allow outgoing TCP
echo "-> allow outgoing $outgoing_tcp"
$IPT -A OUTPUT 	-o $EXT_IF -p tcp -m multiport --dports $outgoing_tcp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT 	-i $EXT_IF -p tcp -m multiport --sports $outgoing_tcp -m state --state ESTABLISHED -j ACCEPT

### Allow outgoing UDP
echo "-> allow outgoing $outgoing_udp"
$IPT -A OUTPUT 	-o $EXT_IF -p udp -m multiport --dports $outgoing_udp -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT 	-i $EXT_IF -p udp -m multiport --sports $outgoing_udp -m state --state ESTABLISHED -j ACCEPT

### Make sure to drop bad packages
echo "-> drop bad packages"
$IPT -A INPUT -f -j DROP # Drop packages with incoming fragments
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP # Drop incoming malformed XMAS packets
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP # Drop all NULL packets
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP # Drop all new connection are not SYN packets

### ICMP (PING) - Ping flood projection 1 per second
echo "-> allow ping"
$IPT -A INPUT -p icmp -m limit --limit 5/s -j ACCEPT
$IPT -A INPUT -p icmp -j DROP

### Log all the rest before dropping
$IPT -A INPUT   -j LOG --log-prefix "IN: "
$IPT -A INPUT   -j DROP
$IPT -A OUTPUT  -j LOG --log-prefix "OU: "
$IPT -A OUTPUT  -j DROP
$IPT -A FORWARD -j LOG --log-prefix "FW: "
$IPT -A FORWARD -j DROP

### End
echo "DONE."
