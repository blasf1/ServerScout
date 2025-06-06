#!/bin/bash
# Sets up nftables and iptables rules, processes ASN and IP blacklists

# Load configuration from .env file
ENV_FILE="$(dirname "$0")/.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
else
    echo "Missing .env file with configuration. Exiting."
    exit 1
fi
touch "$CACHE_FILE"

# Helper: Check if an iptables rule exists
rule_exists() {
    iptables -L INPUT -v | grep -q "NEW-CONN"
}

# Add logging rules for new incoming connections
if ! rule_exists; then
    iptables -I INPUT -i "$IFACE" ! -s 127.0.0.0/8 -m conntrack --ctstate NEW -j LOG --log-prefix "NEW-CONN: "
    iptables -I DOCKER-USER -i "$IFACE" ! -s 127.0.0.0/8 -m conntrack --ctstate NEW -j LOG --log-prefix "NEW-CONN: "
else
    echo "iptables rules already exist, skipping insertion."
fi

# Initialize nftables structures
sudo nft list table "$NFT_TABLE" "$NFT_CUSTOM_TABLE" &>/dev/null || sudo nft add table "$NFT_TABLE" "$NFT_CUSTOM_TABLE"

sudo nft add chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_INPUT" \
  "{ type filter hook input priority filter -1; policy accept; }" 2>/dev/null || \
  echo "Chain $NFT_CHAIN_INPUT already exists"

sudo nft add chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_FORWARD" \
  "{ type filter hook forward priority filter -1; policy accept; }" 2>/dev/null || \
  echo "Chain $NFT_CHAIN_FORWARD already exists"

sudo nft add set "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" \
  '{ type ipv4_addr; flags interval; }' 2>/dev/null || \
  echo "Set $NFT_SET exists"

sudo nft flush set "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET"

# Caching helpers
get_cached_prefixes() {
    local asn="$1"
    grep -E "^$asn=" "$CACHE_FILE" | cut -d'=' -f2
}

cache_prefixes() {
    local asn="$1"
    local prefixes="$2"
    grep -vE "^$asn=" "$CACHE_FILE" > "${CACHE_FILE}.tmp"
    echo "$asn=$prefixes" >> "${CACHE_FILE}.tmp"
    mv "${CACHE_FILE}.tmp" "$CACHE_FILE"
}

# Function to block an ASN using nftables and cache
block_asn() {
    local asn="$1"
    local asn_num=${asn#AS}

    echo "Checking prefix cache for $asn..."
    local prefixes=$(get_cached_prefixes "$asn")
    if [[ -z "$prefixes" ]]; then
        echo "No cache for $asn, fetching from BGPView..."
        prefixes=$(curl -s "https://api.bgpview.io/asn/$asn_num/prefixes" | jq -r '.data.ipv4_prefixes[].prefix' | tr '\n' ',' | sed 's/,$//')
        if [[ -z "$prefixes" ]]; then
            echo "⚠️  Warning: No prefixes found for $asn"
            return
        fi
        cache_prefixes "$asn" "$prefixes"
        sleep 5 # Rate limit API calls
    else
        echo "✅ Using cached prefixes for $asn"
    fi

    IFS=',' read -ra prefix_array <<< "$prefixes"
    for prefix in "${prefix_array[@]}"; do
        echo "Adding $prefix to $NFT_SET"
        sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $prefix }"
    done
}

# Function to block a single IP or prefix
block_ip() {
    ip=$(echo "$entry" | cut -d';' -f1 | xargs)
    echo "Adding $ip to $NFT_SET"
    sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "$ip"
}

# Add drop rules if missing
if ! sudo nft list chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_INPUT" | grep -q "ip saddr @$NFT_SET drop"; then
    sudo nft add rule "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_INPUT" ip saddr @"$NFT_SET" drop
fi
if ! sudo nft list chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_FORWARD" | grep -q "ip saddr @$NFT_SET drop"; then
    sudo nft add rule "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_FORWARD" ip saddr @"$NFT_SET" drop
fi

# Parse blacklist entries
reading_asns=false
while IFS=";" read -r asn comment; do
    asn=$(echo "$asn" | sed 's/^ *//;s/ *$//')
    [[ "$asn" =~ ^\[.*\]$ ]] && {
        reading_asns=$([[ "$asn" == "[blacklist]" ]] && echo true || echo false)
        continue
    }
    $reading_asns && [[ -n "$asn" ]] && block_asn "$asn"
done < "$ASN_LISTS"

# Parse IP blacklist
reading_ips=false
while IFS= read -r line; do
    ip=$(echo "$line" | sed 's/^ *//;s/ *$//')
    [[ "$ip" =~ ^\[.*\]$ ]] && {
        reading_ips=$([[ "$ip" == "[ip_blacklist]" ]] && echo true || echo false)
        continue
    }
    $reading_ips && [[ -n "$ip" ]] && block_ip "$ip"
done < "$ASN_LISTS"

echo "✅ ASN/IP blocking setup complete"
