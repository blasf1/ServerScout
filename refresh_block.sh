#!/bin/bash
# Safely refresh ASN prefix cache and apply diffs to nftables

ENV_FILE="$(dirname "$0")/.env"
if [[ -f "$ENV_FILE" ]]; then
    source "$ENV_FILE"
else
    echo "Missing .env file. Exiting."
    exit 1
fi

if [ ! -f "$ASN_LISTS" ]; then
  echo "Error: ASN config file '$ASN_LISTS' not found."
  exit 1
fi

touch "$CACHE_FILE"

declare -A OLD_PREFIXES

# Load old cache into associative array
while IFS='=' read -r asn prefixes; do
    OLD_PREFIXES["$asn"]="$prefixes"
done < "$CACHE_FILE"

TEMP_CACHE=$(mktemp)

reading_asns=false
while IFS= read -r line; do
    entry=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [[ -z "$entry" ]] && continue

    case "$entry" in
        "[blacklist]")
            reading_asns=true
            continue
            ;;
        \[*)
            reading_asns=false
            continue
            ;;
    esac

    if $reading_asns; then
        sleep 2
        asn=$(echo "$entry" | cut -d';' -f1 | xargs)
        [[ "$asn" != AS* ]] && continue
        asn_num=${asn#AS}

        echo "Fetching prefixes for $asn..."
        json=$(curl -s "https://api.bgpview.io/asn/$asn_num/prefixes")

        if ! echo "$json" | jq -e '.data.ipv4_prefixes' >/dev/null 2>&1; then
            echo "⚠️  API error or invalid data for $asn, keeping old cache"
            if [[ -n "${OLD_PREFIXES[$asn]}" ]]; then
                echo "$asn=${OLD_PREFIXES[$asn]}" >> "$TEMP_CACHE"
            else
                echo "⚠️  No old cache found for $asn, skipping entry"
            fi
            continue
        fi

        new_list=$(echo "$json" | jq -r '.data.ipv4_prefixes[].prefix // empty')
        new_set=($(echo "$new_list"))

        IFS=',' read -ra old_set <<< "${OLD_PREFIXES[$asn]}"
        declare -A old_map new_map

        for ip in "${old_set[@]}"; do old_map["$ip"]=1; done
        for ip in "${new_set[@]}"; do new_map["$ip"]=1; done

        # Compute diffs
        for ip in "${old_set[@]}"; do
            [[ -z "${new_map[$ip]}" ]] && {
                echo "🔻 Removing old prefix $ip (no longer in $asn)"
                sudo nft delete element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $ip }"
            }
        done

        for ip in "${new_set[@]}"; do
            [[ -z "${old_map[$ip]}" ]] && {
                echo "➕ Adding new prefix $ip (from $asn)"
                sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $ip }"
            }
        done

        echo "$asn=$(IFS=','; echo "${new_set[*]}")" >> "$TEMP_CACHE"
    fi
done < "$ASN_LISTS"

mv "$TEMP_CACHE" "$CACHE_FILE"
echo "✅ ASN prefix cache diffed and updated."

# Now refresh static IPs
echo "⏳ Refreshing static IPs..."

reading_ips=false
while IFS= read -r line; do
    entry=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [[ -z "$entry" ]] && continue

    case "$entry" in
        "[ip_blacklist]")
            reading_ips=true
            continue
            ;;
        \[*)
            reading_ips=false
            continue
            ;;
    esac

    if $reading_ips; then
        ip=$(echo "$entry" | cut -d';' -f1 | xargs)
        echo "➕ Adding static IP $ip"
        sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $ip }" 2>/dev/null || true
    fi
done < "$ASN_LISTS"

echo "✅ Static IPs refreshed."
