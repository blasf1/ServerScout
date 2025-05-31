# 🛡️ ServerScout

**ServerScout** is a lightweight Bash-based monitor for public-facing servers. It watches for new incoming IP connections and sends structured alerts to a Discord channel using webhooks. The goal is to give you visibility into unwanted connections—potential scans, probes, or intrusions—in a simple and maintainable way.

---

## ✨ What It Does

- Parses system logs for new incoming connections
- Sends alerts to Discord with enriched context:
  - IP geolocation and ASN
  - AbuseIPDB threat categories and confidence score
  - VirusTotal malware reports and suspicious URLs
  - GreyNoise scanner classification and metadata

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
🧬 Malware Reports: 🚨 3 malicious reports (VT) | 🔗 URLs: http://malicious.ru/scan, http://malicious.ru/exploit
👁️ GreyNoise: 🚨 SNMP Probe: malicious 📡 Noise
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

### 4. Set up iptables logging rules
Run the `setup.sh` script to insert iptables rules that log new incoming connections:
```bash
sudo ./setup.sh
```
This sets up logging rules for the interface `eth0`. Modify the script if your network interface is different.

### 5.Run on boot with systemd
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

## 📝 Notes

- This script watches all **new incoming connections** on any protocol by inspecting log entries with the `NEW-CONN:` prefix, which is inserted via iptables rules.
- It does not capture established or outgoing connections.
- You must have logging enabled and a firewall that logs new traffic — this is handled by the `setup.sh` script.
- IPs are only reported once every 15 minutes to avoid repeated alerts.
- If you don't run any firewalls or protections (like [**Geoip-shell**](https://github.com/friendly-bits/geoip-shell.git) and [**CrowdSec**](https://github.com/crowdsecurity/crowdsec)) in your server you will get excessive alerts.

## 📄 License

This project is licensed under the **GNU General Public License v3.0**.

This means:

- ✅ You are free to use, study, share, and modify this software.
- 🔁 Any modified versions **must** also be distributed under the same license.
- 📢 Derivative works **must remain open-source**.

See the [LICENSE](./LICENSE) file for full terms.

