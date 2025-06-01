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

# Extract ASNs from the blacklist section of the INI file
while IFS=";" read -r asn comment; do
  # Remove leading/trailing whitespace and skip empty lines or section headers
  asn=$(echo "$asn" | sed 's/^ *//;s/ *$//')
  [[ -z "$asn" || "$asn" == \[blacklist\] ]] && continue

  ASN_NUM=${asn#AS}
  echo "Fetching prefixes for $asn..."

  PREFIXES=$(curl -s "https://api.bgpview.io/asn/$ASN_NUM/prefixes" | jq -r '.data.ipv4_prefixes[].prefix')

  if [ -z "$PREFIXES" ]; then
    echo "Warning: No prefixes found for $asn"
    continue
  fi

  for prefix in $PREFIXES; do
    echo "Adding $prefix to $NFT_SET"
    sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $prefix }"
  done
done < <(sed -n '/\[blacklist\]/,/\[.*\]/p; /\[blacklist\]/,$p' "$ASN_LISTS")

echo "ASN prefixes updated successfully."
