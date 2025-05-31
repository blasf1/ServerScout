#!/bin/bash
# Restores iptables logging rules for new incoming connections on eth0

# Adjust interface name if different
IFACE="eth0"

iptables -I INPUT -i "$IFACE" ! -s 127.0.0.0/8 -m conntrack --ctstate NEW -j LOG --log-prefix "NEW-CONN: "
iptables -I DOCKER-USER -i "$IFACE" ! -s 127.0.0.0/8 -m conntrack --ctstate NEW -j LOG --log-prefix "NEW-CONN: "
