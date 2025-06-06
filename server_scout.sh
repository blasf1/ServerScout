#!/bin/bash

# Load secrets from .env file if it exists
ENV_FILE="$(dirname "$0")/.env"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
else
    echo "Missing .env file with API keys. Exiting."
    exit 1
fi

touch "$CACHE_FILE"
LOG_FILE="/var/log/syslog"
declare -A LAST_SEEN_IPS

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

is_in_whitelist() {
    local asn="$1"
    sed -n '/\[whitelist\]/,/\[blacklist\]/p' "$ASN_LISTS" \
        | grep -v '^\[' \
        | grep -qE "^$asn(\s|;)"
}

is_in_blacklist() {
    local asn="$1"
    sed -n '/\[blacklist\]/,$p' "$ASN_LISTS" \
        | grep -v '^\[' \
        | grep -qE "^$asn(\s|;)"
}

is_ip_blacklisted() {
    local ip="$1"
    sed -n '/\[ip_blacklist\]/,$p' "$ASN_LISTS" \
        | grep -v '^\[' \
        | grep -qE "^$ip(\s|;)"
}

add_ip_to_blacklist() {
    local ip="$1"
    local comment="$2"
    local tmpfile=$(mktemp)

    awk -v ip="$ip" -v comment="$comment" '
        BEGIN {added=0}
        /^\[ip_blacklist\]/ {
            print
            if (!seen) {
                print ip " ; " comment
                seen=1
            }
            next
        }
        { print }
    ' "$ASN_LISTS" > "$tmpfile" && mv "$tmpfile" "$ASN_LISTS"

    # Block IP using nftables
    sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $ip }"
}

add_to_blacklist() {
    local asn="$1"
    local comment="$2 (autoblocked by ServerScout)"
    local tmpfile=$(mktemp)

    awk -v asn="$asn" -v comment="$comment" '
        BEGIN {added=0}
        /^\[blacklist\]/ {
            print
            if (!seen) {
                print asn " ; " comment
                seen=1
            }
            next
        }
        { print }
    ' "$ASN_LISTS" > "$tmpfile" && mv "$tmpfile" "$ASN_LISTS"
    
    # Block the ASN using nftables
    block_asn "$asn"
}

# Function to block an ASN using nftables
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
    else
        echo "✅ Using cached prefixes for $asn"
    fi

    IFS=',' read -ra prefix_array <<< "$prefixes"
    for prefix in "${prefix_array[@]}"; do
        echo "Adding $prefix to $NFT_SET"
        sudo nft add element "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_SET" "{ $prefix }"
    done

    # Add drop rule to input chain if missing
    if ! sudo nft list chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_INPUT" | grep -q "ip saddr @$NFT_SET drop"; then
        sudo nft add rule "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_INPUT" ip saddr @"$NFT_SET" drop
    fi

    # Add drop rule to forward chain if missing
    if ! sudo nft list chain "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_FORWARD" | grep -q "ip saddr @$NFT_SET drop"; then
        sudo nft add rule "$NFT_TABLE" "$NFT_CUSTOM_TABLE" "$NFT_CHAIN_FORWARD" ip saddr @"$NFT_SET" drop
    fi
}

# Check if IP is allowed (i.e., not seen within cooldown window)
should_process_ip() {
    local ip="$1"
    local now=$(date +%s)
    local last_seen=${LAST_SEEN_IPS[$ip]:-0}

    if (( now - last_seen >= COOLDOWN_SECONDS )); then
        LAST_SEEN_IPS[$ip]=$now
        return 0  # Yes, process this IP
    else
        return 1  # Cooldown not expired
    fi
}

# Function to extract top threat tags from AbuseIPDB reports
extract_top_threat_tags() {
    local abuse_json="$1"
    declare -A ABUSE_CATEGORIES=(
        [3]="Fraud Orders" [4]="DDoS Attack" [5]="FTP Brute-Force"
        [6]="Ping of Death" [7]="Phishing" [8]="Fraud VoIP"
        [9]="Open Proxy" [10]="Web Spam" [11]="Email Spam"
        [12]="Blog Spam" [13]="VPN IP" [14]="Port Scan"
        [15]="Hacking" [16]="SQL Injection" [17]="Spoofing"
        [18]="Brute-Force" [19]="Bad Web Bot" [20]="Exploited Host"
        [21]="Web App Attack" [22]="SSH" [23]="IoT Targeted"
    )

    local categories_list=$(echo "$abuse_json" | jq '[.data.reports[].categories[]] // []')
    declare -A category_counts
    for cat_id in $(echo "$categories_list" | jq -r '.[]'); do
        ((category_counts[$cat_id]++))
    done

    # Create a temporary list of sortable "count category" lines
    local sortable_lines=()
    for cat_id in "${!category_counts[@]}"; do
        local tag="${ABUSE_CATEGORIES[$cat_id]}"
        local count=${category_counts[$cat_id]}
        [[ -n "$tag" ]] && sortable_lines+=("$count $tag")
    done

    # Sort numerically and select top 3
    IFS=$'\n' sorted=($(printf "%s\n" "${sortable_lines[@]}" | sort -nr | head -n 3))

    # Format final tags list
    local output_tags=()
    for line in "${sorted[@]}"; do
        local count=$(echo "$line" | awk '{print $1}')
        local tag=$(echo "$line" | cut -d' ' -f2-)
        output_tags+=("$tag (x$count)")
    done

    if [[ ${#output_tags[@]} -eq 0 ]]; then
        echo "None"
    else
        IFS=", "; echo "${output_tags[*]}"
    fi
}

# Function to get VirusTotal info
get_virustotal_info() {
    local ip="$1"
    local vt_summary="Unavailable"

    if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
        local vt_response=$(curl -s -H "x-apikey: $VIRUSTOTAL_API_KEY" \
            "https://www.virustotal.com/api/v3/ip_addresses/$ip")

        local malicious_count=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
        local sample_refs=$(echo "$vt_response" | jq -r '[.data.attributes.detected_urls[0:3][]?.url] | join(", ")' 2>/dev/null)

        if [[ "$malicious_count" -gt 0 ]]; then
            vt_summary="🚨 $malicious_count malicious reports"
            [[ -n "$sample_refs" ]] && vt_summary+=" | 🔗 URLs: $sample_refs"
        else
            vt_summary="✅ No detections"
        fi
    fi

    echo "$vt_summary"
}

# Function to get GreyNoise info
get_greynoise_info() {
    local ip="$1"

    if [[ -n "$GREYNOISE_API_KEY" ]]; then
        local response=$(curl -s -H "key: $GREYNOISE_API_KEY" \
            "https://api.greynoise.io/v3/community/$ip")

        if echo "$response" | jq . >/dev/null 2>&1; then
            local message=$(echo "$response" | jq -r '.message // empty')

            if [[ "$message" == "IP not observed scanning the internet or contained in RIOT data set." ]]; then
                echo "⚪ Not observed"
                return
            fi

            local classification=$(echo "$response" | jq -r '.classification // empty')
            local noise=$(echo "$response" | jq -r '.noise // false')
            local riot=$(echo "$response" | jq -r '.riot // false')
            local name=$(echo "$response" | jq -r '.name // empty')

            # Handle empty classification/name cases
            if [[ -z "$classification" || -z "$name" ]]; then
                return  # silently skip if missing core data
            fi

            local emoji="⚪"
            case "$classification" in
                "malicious") emoji="🚨";;
                "benign") emoji="✅";;
                "unknown") emoji="⚠️";;
                "none") emoji="⚪";;
            esac

            local summary="$emoji $name: $classification"
            [[ "$noise" == "true" ]] && summary+=" 📡 Noise"
            [[ "$riot" == "true" ]] && summary+=" 🧩 RIOT"

            echo "$summary"
        fi
    fi
}

# Function to get AbuseIPDB info
get_abuseipdb_info() {
    local ip="$1"
    local abuse_info=$(curl -sG https://api.abuseipdb.com/api/v2/check \
        --data-urlencode "ipAddress=$ip" \
        --data-urlencode "verbose=true" \
        -H "Key: $ABUSE_API_KEY" \
        -H "Accept: application/json")

    local abuse_score=$(echo "$abuse_info" | jq -r '.data.abuseConfidenceScore')
    abuse_score=${abuse_score:-0}

    local threat_tags=$(extract_top_threat_tags "$abuse_info")

    echo "$abuse_score $threat_tags"
}

# Function to send notification to Discord using embed
send_discord_notification() {
    local ip="$1"
    local proto="$2"
    local port="$3"
    local service="$4"
    local abuse_score="$5"
    local threat_tags="$6"
    local vt_samples="$7"
    local gn_info="$8"
    local country="$9"
    local countryCode="${10}"
    local asn="${11}"
    local asn_block_status="${12}"

    local info=$(curl -s "http://ip-api.com/json/$ip?fields=status,country,countryCode,as,query,message")
    local status=$(echo "$info" | jq -r '.status')

    if [[ "$status" == "success" ]]; then
        local timestamp=$(date +"%H:%M:%S %d-%m-%Y")
        local flag=":flag_${countryCode,,}:"

        # Determine color based on abuse score
        local color=65280  # Green
        if (( abuse_score >= 50 )); then
            color=16711680  # Red
        elif (( abuse_score >= 1 )); then
            color=16776960  # Yellow
        fi

        local description="🕒 **Time:** \`$timestamp\`
🌐 **IP:** \`$ip\`
🏳️ **Country:** $flag $country
🛰️ **ASN:** \`$asn\`
⚠️ **Abuse Score:** \`$abuse_score/100\`
🔍 **Protocol:** \`$proto\`
🎯 **Port:** \`$port ($service)\`
☣️ **Threat Tags:** $threat_tags
🧬 **Virus Total:** $vt_samples"
[[ -n "$gn_info" ]] && description+="
👁️ **GreyNoise:** $gn_info"
[[ -n "$asn_block_status" ]] && description+="
🛡️ **ASN Block Status:** $asn_block_status"

        local json_payload=$(jq -n \
          --arg title "📡 New IP connection detected" \
          --arg description "$description" \
          --argjson color "$color" \
          '{
            embeds: [
              {
                title: $title,
                description: $description,
                color: $color
              }
            ]
          }')

        curl -s -H "Content-Type: application/json" -X POST \
            -d "$json_payload" \
            "$DISCORD_WEBHOOK_URL" > /dev/null
    else
        echo "Failed to retrieve info for $ip"
    fi
}

# Function to handle abuse score and blacklisting
handle_abuse_score_and_blacklist() {
    local ip="$1"
    local abuse_score="$2"
    local asn="$3"
    local country="$4"
    local asn_name="$5"

    local asn_number=$(echo "$asn" | grep -oE 'AS[0-9]+' | head -n 1)
    if [[ -z "$asn_number" ]]; then
        if (( abuse_score > ABUSE_SCORE_THRESHOLD )); then
            add_ip_to_blacklist "$ip" "Unknown ASN (autoblocked by ServerScout)"
            echo "⚠️ Unknown ASN - ⛔ IP banned"
        else
            echo "⚠️ Unknown ASN"
        fi
        return
    fi

    if is_in_whitelist "$asn_number"; then
        if (( abuse_score > 10 )); then
            add_ip_to_blacklist "$ip" "ASN $asn_number ($asn_name) from $country (autoblocked by ServerScout)"
            echo "✅ ASN Whitelisted - 🔥⛔ IP banned"
        else
            echo "✅ ASN Whitelisted"
        fi
        return
    elif is_in_blacklist "$asn_number"; then
        if (( abuse_score > 10 )); then
            add_ip_to_blacklist "$ip" "ASN $asn_number ($asn_name) from $country (autoblocked by ServerScout)"
            echo "⛔ ASN Already blacklisted - 🔥⛔ IP banned"
        else
            echo "⛔ ASN Already blacklisted"
        fi
        return
    elif (( abuse_score > 10 )); then
        add_to_blacklist "$asn_number" "$asn_name ($country)" >/dev/null 2>&1;
        echo "🔥⛔ Banning ASN"
        return
    fi

    echo "🟡 Not blacklisted (low abuse score)"
}

# Function to clean up old IPs (older than 15 min)
cleanup_old_ips() {
    local now=$(date +%s)
    local tmpfile=$(mktemp)

    while IFS=" " read -r ip timestamp; do
        [[ -z "$ip" || -z "$timestamp" ]] && continue
        local ts_epoch=$(date -d "$timestamp" +%s 2>/dev/null)
        if [[ $((now - ts_epoch)) -lt 900 ]]; then
            echo "$ip $timestamp" >> "$tmpfile"
        fi
    done < "$LAST_IP_FILE"

    mv "$tmpfile" "$LAST_IP_FILE"
}

get_service_name() {
    case "$1" in
        22) echo "SSH";;
        80) echo "HTTP";;
        443) echo "HTTPS";;
        21) echo "FTP";;
        25) echo "SMTP";;
        3306) echo "MySQL";;
        5432) echo "PostgreSQL";;
        6379) echo "Redis";;
        41641) echo "Tailscale";;
        *) echo "$1";;
    esac
}

# Tail the log file and watch for new connections
tail -F "$LOG_FILE" | while read -r line; do
    if [[ "$line" == *"NEW-CONN: "* ]]; then
        ip=$(echo "$line" | grep -oE 'SRC=([0-9]{1,3}\.){3}[0-9]{1,3}' | cut -d'=' -f2)
        proto=$(echo "$line" | grep -oP 'PROTO=\K\S+' || echo "N/A")
        port=$(echo "$line" | grep -oP 'DPT=\K\S+' || echo "0")
        service=$(get_service_name "$port")

        if [[ -n "$ip" ]] && should_process_ip "$ip"; then
            info=$(curl -s "http://ip-api.com/json/$ip?fields=status,country,countryCode,as,query,message")
            status=$(echo "$info" | jq -r '.status')

            if [[ "$status" == "success" ]]; then
                country=$(echo "$info" | jq -r '.country')
                countryCode=$(echo "$info" | jq -r '.countryCode')
                asn=$(echo "$info" | jq -r '.as')

                read -r abuse_score threat_tags <<< $(get_abuseipdb_info "$ip")
                vt_samples=$(get_virustotal_info "$ip")
                gn_info=$(get_greynoise_info "$ip")
                
                # Extract ASN name from the ASN string
                asn_name=$(echo "$asn" | sed 's/^AS[0-9]\+ //')
                asn_block_status=$(handle_abuse_score_and_blacklist "$ip" "$abuse_score" "$asn" "$country" "$asn_name")

                # Send notification to Discord
                send_discord_notification "$ip" "$proto" "$port" "$service" "$abuse_score" "$threat_tags" "$vt_samples" "$gn_info" "$country" "$countryCode" "$asn" "$asn_block_status"
            fi
        fi
    fi
done