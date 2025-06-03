#!/bin/bash
# Restores iptables logging rules for new incoming connections on eth0

# Load configuration from .env file
ENV_FILE="$(dirname "$0")/.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
else
    echo "Missing .env file with configuration. Exiting."
    exit 1
fi

# Wait for the network interface to be up
until ip link show "$IFACE" | grep -q "state UP"; do
  echo "Waiting for $IFACE to be up..."
  sleep 2
done

# Wait for network to be up
until ping -c1 google.com &>/dev/null; do
  echo "Waiting for network..."
  sleep 2
done

# Function to check if an iptables rule exists
rule_exists() {
    iptables -L INPUT -v | grep -q "NEW-CONN"
}

# Set up iptables logging for new connections if the rule does not exist
if ! rule_exists; then
    iptables -I INPUT -i "$IFACE" ! -s 127.0.0.0/8 -m conntrack --ctstate NEW -j LOG --log-prefix "NEW-CONN: "
    iptables -I DOCKER-USER -i "$IFACE" ! -s 127.0.0.0/8 -m conntrack --ctstate NEW -j LOG --log-prefix "NEW-CONN: "
else
    echo "iptables rules already exist, skipping insertion."
fi

# Create the custom table if it doesn't exist
sudo nft list table "$NFT_TABLE" "$NFT_CUSTOM_TABLE" 2>/dev/null >/dev/null || \
  sudo nft add table "$NFT_TABLE" "$NFT_CUSTOM_TABLE"

# Create input chain with priority after crowdsec (-10) and before default (0)
sudo nft add chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_INPUT" \
  "{ type filter hook input priority filter -1; policy accept; }" 2>/dev/null || \
  echo "Chain $NFT_CHAIN_INPUT already exists"

# Create forward chain with same priority
sudo nft add chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_FORWARD" \
  "{ type filter hook forward priority filter -1; policy accept; }" 2>/dev/null || \
  echo "Chain $NFT_CHAIN_FORWARD already exists"

# Create the set (ignore if it already exists)
sudo nft add set "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" \
  '{ type ipv4_addr; flags interval; }' 2>/dev/null || \
  echo "Set $NFT_SET exists"

# Flush the set for fresh population
sudo nft flush set "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET"

# Function to block an ASN using nftables
block_asn() {
    local asn="$1"
    local asn_num=${asn#AS}

    echo "Fetching prefixes for $asn..."
    local prefixes=$(curl -s "https://api.bgpview.io/asn/$asn_num/prefixes" | jq -r '.data.ipv4_prefixes[].prefix')

    if [ -z "$prefixes" ]; then
        echo "Warning: no prefixes found for $asn"
        return
    fi

    for prefix in $prefixes; do
        echo "Adding $prefix to $NFT_SET"
        sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $prefix }"
    done
}

# Function to block a single IP or prefix
block_ip() {
    ip=$(echo "$entry" | cut -d';' -f1 | xargs)
    echo "Adding $ip to $NFT_SET"
    sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $ip }"
}

# Add drop rule to input chain if missing
if ! sudo nft list chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_INPUT" | grep -q "ip saddr @$NFT_SET drop"; then
    sudo nft add rule "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_INPUT" ip saddr @"$NFT_SET" drop
fi

# Add drop rule to forward chain if missing
if ! sudo nft list chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_FORWARD" | grep -q "ip saddr @$NFT_SET drop"; then
    sudo nft add rule "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_FORWARD" ip saddr @"$NFT_SET" drop
fi

# Process [blacklist] section (ASNs)
reading_asns=false
while IFS=";" read -r asn comment; do
    asn=$(echo "$asn" | sed 's/^ *//;s/ *$//')

    # Detect section headers
    if [[ "$asn" =~ ^\[.*\]$ ]]; then
        if [[ "$asn" == "[blacklist]" ]]; then
            reading_asns=true
        else
            reading_asns=false
        fi
        continue
    fi

    if $reading_asns && [[ -n "$asn" ]]; then
        block_asn "$asn"
    fi
    sleep 2
done < "$ASN_LISTS"

# Process [ip_blacklist] section (IP addresses or CIDRs)
reading_ips=false
while IFS= read -r line; do
    ip=$(echo "$line" | sed 's/^ *//;s/ *$//')

    # Detect section headers
    if [[ "$ip" =~ ^\[.*\]$ ]]; then
        if [[ "$ip" == "[ip_blacklist]" ]]; then
            reading_ips=true
        else
            reading_ips=false
        fi
        continue
    fi

    if $reading_ips && [[ -n "$ip" ]]; then
        block_ip "$ip"
    fi
done < "$ASN_LISTS"

echo "✅ ASN blocking setup complete"
