#!/bin/bash

# Load configuration from .env file
ENV_FILE="$(dirname "$0")/.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
else
    echo "Missing .env file with configuration. Exiting."
    exit 1
fi

# Check if the ASN config file exists
if [ ! -f "$ASN_LISTS" ]; then
  echo "Error: ASN config file '$ASN_LISTS' not found."
  exit 1
fi

# Flush existing prefixes in the set
sudo nft flush set "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET"

# Flags to track section
reading_asns=false
reading_ips=false

while IFS= read -r line; do
  entry=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [[ -z "$entry" ]] && continue

  case "$entry" in
    "[blacklist]")
      reading_asns=true
      reading_ips=false
      continue
      ;;
    "[ip_blacklist]")
      reading_asns=false
      reading_ips=true
      continue
      ;;
    \[*)
      reading_asns=false
      reading_ips=false
      continue
      ;;
  esac

  if $reading_asns; then
    sleep 2 # Rate limit to avoid hitting API too fast

    # Skip empty or comment-only lines
    [[ -z "$entry" || "$entry" =~ ^\s*# ]] && continue

    # Strip inline comments (anything after ;) and trim whitespace
    asn=$(echo "$entry" | cut -d';' -f1 | xargs)

    # Ensure it starts with AS
    [[ "$asn" != AS* ]] && continue

    # Extract ASN number only
    asn_num=${asn#AS}

    echo "Fetching prefixes for $asn..."
    
    json=$(curl -s "https://api.bgpview.io/asn/$asn_num/prefixes")

    # Validate: is it JSON and does it contain ipv4_prefixes?
    if ! echo "$json" | jq -e '.data.ipv4_prefixes' >/dev/null 2>&1; then
        echo "Warning: Invalid JSON or missing data for $asn"
        continue
    fi

    prefixes=$(echo "$json" | jq -r '.data.ipv4_prefixes[].prefix // empty')

    if [ -z "$prefixes" ]; then
      echo "Warning: No prefixes found for AS$asn_num"
      continue
    fi

    for prefix in $prefixes; do
      echo "Adding $prefix to $NFT_SET"
      sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $prefix }"
    done
  elif $reading_ips; then
    ip=$(echo "$entry" | cut -d';' -f1 | xargs)
    echo "Adding $ip to $NFT_SET"
    sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $ip }"
  fi

done < "$ASN_LISTS"

echo "✅ ASN and IP prefixes updated successfully."
