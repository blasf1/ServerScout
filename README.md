# 🛡️ ServerScout

**ServerScout** is a lightweight Bash-based monitor for public-facing servers. It watches for new incoming IP connections and sends structured alerts to a Discord channel using webhooks. The goal is to give you visibility into unwanted connections—potential scans, probes, or intrusions—in a simple and maintainable way.

---

## ✨ What It Does

- Parses system logs for new incoming connections
- Sends alerts to Discord with enriched context:
  - 🌍 IP geolocation and ASN data
  - ☣️ AbuseIPDB threat categories and confidence score
  - 🧬 VirusTotal detection counts and related malicious URLs
  - 👁️ GreyNoise scanner classifications and noise/RIOT info
- 🔥 Automatically blacklists high-abuse ASNs via `nftables`

It’s meant for curious server owners who want basic but useful insight into who's knocking at their ports without being stopped by other protections like [**Geoip-shell**](https://github.com/friendly-bits/geoip-shell.git) and [**CrowdSec**](https://github.com/crowdsecurity/crowdsec)'s firewall bouncer (otherwise you will get a deluge of notifications).

## 📷 Example Notification

```text
📡 New IP connection detected
🕒 Time: 2025-05-31 18:23:49
🌐 IP: 45.135.233.10
🏳️ Country: 🇷🇺 Russia
🛰️ ASN: AS48666 JSC "RU-CENTER"
⚠️ Abuse Score: 72/100
🔍 Protocol: UDP
🎯 Port: 161 (SNMP)
☣️ Threat Tags: Port Scan (9), Hacking (4)
🧬 Malware Reports: 🚨 3 malicious reports (VT)
👁️ GreyNoise: 🚨 SNMP Probe: malicious 📡 Noise
🛡️ ASN Block Status: 🔥⛔ Newly blacklisted
```

## ⚙️ Setup

### 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y curl jq
```

### 2. Clone the repository:

```bash
git clone https://github.com/blasf1/ServerScout.git
cd ServerScout
```

Set executable permissions:

```bash
chmod +x server_scout.sh setup.sh
```

### 3. Configure environment

Copy the `.env.example` to `.env`:

```bash
cp .env.example .env
```

Then edit it to include your API keys and Discord webhook URL.

Copy the example blacklist and whitelist file:

```bash
cp lists.ini.example lists.ini
```

Then edit it to include your whitelist (trusted ASNs). You can also blacklist specific ASNs manually. ServerScout will automatically populate the blacklist with hostile ASNs it detects over time.

### 4. Set up iptables logging rules

Run the `setup.sh` script to insert iptables rules that log new incoming connections:

```bash
sudo ./setup.sh
```

This sets up logging rules for the interface `eth0`. Modify the script if your network interface is different.

### 5. Run on boot with systemd

To run the script automatically in the background on boot let's create a systemd service. Create `/etc/systemd/system/serverscout.service` with the following contents:

```
[Unit]
Description=ServerScout - Incoming Connection Monitor
After=network.target

[Service]
ExecStart=/path/to/server_scout.sh
WorkingDirectory=/path/to
Restart=always
EnvironmentFile=/path/to/.env

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reexec
sudo systemctl enable serverscout
sudo systemctl start serverscout
```

### 6. Make rules persist after reboot

The ipset and iptables rules are not persistent by default. To ensure the ASN blocks and connection monitor are restored after a reboot. To ensure docker and network are already available, create a one shot service in `/etc/systemd/system/serverscout-setup.service` with the following contents:

```
# /etc/systemd/system/serverscout-setup.service
[Unit]
Description=Setup ServerScout iptables and nftables rules
After=network.target docker.service
Requires=network.target docker.service

[Service]
Type=oneshot
ExecStart=/path/to/setup.sh
RemainAfterExit=yes
EnvironmentFile=/path/to/.env

[Install]
WantedBy=multi-user.target
```

Enable the service:

```bash
sudo systemctl daemon-reexec
sudo systemctl enable serverscout-setup
```

### 7. Ensure that ASNs are kept up to date

ASN-assigned IP prefixes can change over time. To make sure your blocking rules are current, schedule the `refresh_block.sh` script to run daily via cron. This script will automatically refresh the list of IPs associated with the ASNs and apply the updated block rules.

Add the following line to your crontab using `crontab -e`:

```bash
0 3 * * * /root/ServerScout/refresh_block.sh 1>/dev/null 2>/dev/null
```

## 📝 Notes

- 🕵️‍♂️This script watches all **new incoming connections** on any protocol by inspecting log entries with the `NEW-CONN:` prefix, which is inserted via iptables rules.
- 🔥 ASN blocking is done via nftables with IPv4 prefixes pulled from bgpview.io
- It does not capture established or outgoing connections.
- You must have logging enabled and a firewall that logs new traffic — this is handled by the `setup.sh` script.
- 📁 ASNs are managed via the file defined in $ASN_LISTS, which includes `[whitelist]` and `[blacklist]` sections. The blacklist is automatically updated by ServerScout. Whitelisted ASNs will not be added to the blacklist.
- ⚙️ The `[ip_blacklist]` section supports static IP blocks that are also applied during refresh.
- 🧱 Use this alongside [**Geoip-shell**](https://github.com/friendly-bits/geoip-shell.git), [**CrowdSec**](https://github.com/crowdsecurity/crowdsec), or other firewall rules for best results. If you don't run any firewalls or protections in your server you will get excessive alerts.

## 📄 License

This project is licensed under the **GNU General Public License v3.0**.

This means:

- ✅ You are free to use, study, share, and modify this software.
- 🔁 Any modified versions **must** also be distributed under the same license.
- 📢 Derivative works **must remain open-source**.

See the [LICENSE](./LICENSE) file for full terms.
