#!/bin/bash

# declare some system variables
iptables="/sbin/iptables"
ext_if=$(/sbin/ip route | grep default | awk '{print $5}') # external network interface
int_if=$(/sbin/ip link show | grep "state UP" | grep -v $ext_if | awk '{print $2}' | cut -d':' -f1) # all internal network interfaces

network_addr=$(/sbin/ip route | grep default | awk '{print $3}' | cut -d"." -f1-3)
broadcast_addr="$network_addr.255"

# declare some options to choose
LAN_ALLOW="1" # this will set allow all connection from LAN
BLACKLIST_BLOCK="1" # enable block ips from blacklist
WHITELIST_ALLOW="1" # enable allow ips from whitelist

# list incoming and outgoing TCP & UDP ports (22 is mandatory, not list here)
incoming_tcp="80,443"
incoming_udp="53"
outgoing_tcp="22,53,80"
outgoing_udp="53,123"

# file
black_list="blacklist.txt"
white_list="whitelist.txt"

# check if file is found
if [ $BLACKLIST_BLOCK = "1" ] && [ ! -f $black_list ]; then
	echo "File $black_list not found."
	exit 1
fi

if [ $WHITELIST_ALLOW = "1" ] && [ ! -f "$white_list" ]; then
	echo "File $white_list not found."
	exit 1
fi

### STARTING FIREWALL
echo -n "Starting firewall: "

# tuning network protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies                          # enable TCP SYN cookie protection
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route            # disable IP Source routing
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects               # disable ICMP Redirect acceptance
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter                      # enable IP spoofing protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts             # ignore echo broadcast requests to prevent smurf attacks

# delete all existing rules
$iptables -F
$iptables -X
$iptables -t nat -F
$iptables -t nat -X
$iptables -t mangle -F
$iptables -t mangle -X

# default policy
$iptables -P INPUT   DROP
$iptables -P FORWARD DROP
$iptables -P OUTPUT  DROP

# drop broadcast (do not log)
$iptables -A INPUT -i $ext_if -d 255.255.255.255 -j DROP
$iptables -A INPUT -i $ext_if -d $broadcast_addr -j DROP

# allow allow loopback
$iptables -A INPUT  -i lo -j ACCEPT
$iptables -A OUTPUT -o lo -j ACCEPT

# allow LAN connection
if [ "$LAN_ALLOW" = "1" ]; then
	for eth in $int_if; do
		$iptables -A INPUT -i $eth -j ACCEPT
		$iptables -A OUTPUT -o $eth -j ACCEPT
	done
fi

# allow incoming SSH
$iptables -A INPUT -i $ext_if -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$iptables -A OUTPUT -o $ext_if -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# allow good ip from whitelist file
if [ "$WHITELIST_ALLOW" = "1" ]; then
	$iptables -N acceptlist
	good_ips=$(egrep -v -E "^#|^$" $white_list)
	for ip in $good_ips; do
		$iptables -A acceptlist -s $ip -j ACCEPT
	done
	# insert or append our acceptlist
	$iptables -I INPUT -j acceptlist
	$iptables -I OUTPUT -j acceptlist
	$iptables -I FORWARD -j acceptlist
fi

# block bad ip from blacklist file
if [ "$BLACKLIST_BLOCK" = "1" ]; then
	$iptables -N droplist
	bad_ips=$(egrep -v -E "^#|^$" $black_list)
	for ip in $bad_ips; do
		$iptables -A droplist -s $ip -j LOG --log-prefix "Drop ip in blacklist"
		$iptables -A droplist -s $ip -j DROP
	done
	# insert or append our droplist 
	$iptables -I INPUT -j droplist
	$iptables -I OUTPUT -j droplist
	$iptables -I FORWARD -j droplist
fi

# allow incoming TCP
$iptables -A INPUT -i $ext_if -p tcp -m multiport --dports $incoming_tcp -m state --state NEW,ESTABLISHED -j ACCEPT
$iptables -A OUTPUT -o $ext_if -p tcp -m multiport --sports $incoming_tcp -m state --state ESTABLISHED -j ACCEPT

# allow incoming UDP
$iptables -A INPUT -i $ext_if -p udp -m multiport --dports $incoming_udp -m state --state NEW,ESTABLISHED -j ACCEPT
$iptables -A OUTPUT -o $ext_if -p udp -m multiport --sports $incoming_udp -m state --state ESTABLISHED -j ACCEPT

# allow outgoing TCP
$iptables -A OUTPUT -o $ext_if -p tcp -m multiport --dports $outgoing_tcp -m state --state NEW,ESTABLISHED -j ACCEPT
$iptables -A INPUT -i $ext_if -p tcp -m multiport --sports $outgoing_tcp -m state --state ESTABLISHED -j ACCEPT

# allow outgoing UDP
$iptables -A OUTPUT -o $ext_if -p udp -m multiport --dports $outgoing_udp -m state --state NEW,ESTABLISHED -j ACCEPT
$iptables -A INPUT -i $ext_if -p udp -m multiport --sports $outgoing_udp -m state --state ESTABLISHED -j ACCEPT

# make sure to drop bad packages
$iptables -A INPUT -f -j DROP # Drop packages with incoming fragments
$iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP # Drop incoming malformed XMAS packets
$iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP # Drop all NULL packets
$iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP # Drop all new connection are not SYN packets

# ping flood projection 5 per second
$iptables -A INPUT	-p icmp -m limit --limit 5/s -j ACCEPT
$iptables -A OUTPUT	-p icmp -m limit --limit 5/s -j ACCEPT
$iptables -A INPUT	-p icmp -j DROP
$iptables -A OUTPUT	-p icmp -j DROP

# log all the rest before dropping
$iptables -A INPUT   -j LOG --log-prefix "IN: "
$iptables -A INPUT   -j DROP
$iptables -A OUTPUT  -j LOG --log-prefix "OU: "
$iptables -A OUTPUT  -j DROP
$iptables -A FORWARD -j LOG --log-prefix "FW: "
$iptables -A FORWARD -j DROP

### End
echo "OK."
