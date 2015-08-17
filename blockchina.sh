#!/bin/bash

# Create the ipset list
ipset -N china hash:net

# remove any old list that might exist from previous runs of this script
rm cn.zone

# Pull the latest IP set for China
wget -P . http://www.ipdeny.com/ipblocks/data/countries/cn.zone

# Add each IP address from the downloaded list into the ipset 'china'
for i in $(cat /etc/cn.zone ); do ipset -A china $i; done

# Restore iptables
/sbin/iptables -A INPUT -p tcp -m set --match-set china src -j DROP
