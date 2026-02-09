# nids/QUICKSTART.md
# NIDS Quick Start Guide

Get the Network Intrusion Detection System up and running in 5 minutes.

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
- `scapy`: Packet capture and processing
- `pyyaml`: Configuration file parsing

## 2. Verify Configuration

The default `config/config.yaml` is pre-configured for most networks:

```bash
cat config/config.yaml | head -20
```

### Minimal Configuration (Immediate Start)

The default config enables:
- ✅ ICMP Flood detection (100 packets/10s)
- ✅ TCP SYN Port Scan detection (50 ports/30s)
- ✅ Brute-Force detection (5 attempts/60s)
- ✅ ARP Spoofing detection (10 replies/30s)
- ✅ Console alerts with colors
- ✅ JSON logging to `logs/nids_alerts.json`

**No changes needed to config to start!**

## 3. Run NIDS

### Linux/macOS (with sudo)
```bash
sudo python main.py
```

### Windows (Run PowerShell as Administrator)
```powershell
python main.py
```

Expected output:
```
[*] Configuration loaded successfully
[+] All components initialized successfully
[*] NIDS started on 4 interfaces
[*] 4 detection rules active
```

## 4. Monitor Output

The system prints statistics every 30 seconds:

```
================================================================================
[*] NIDS Statistics - 2025-02-07 14:30:45
================================================================================
  System Status: HEALTHY
  Uptime: 125.3s
  Packets Captured: 45230
  Packets/Second: 361.04
  Total Alerts: 2
    - CRITICAL: 0
    - HIGH: 2
    - MEDIUM: 0
    - LOW: 0
================================================================================
```

## 5. Test Detection Rules (Optional)

### Test 1: Trigger ICMP Flood Alert
From another machine, send ICMP packets:
```bash
ping -f 192.168.1.100  # Linux/macOS: flood ping
# Windows: ping -l 65500 -w 1 -t 192.168.1.100
```

You should see **ICMP_FLOOD** alert in NIDS console.

### Test 2: Trigger TCP SYN Scan Alert
Use nmap to scan ports (from another machine):
```bash
nmap -sS -p 1-1000 192.168.1.100
```

You should see **TCP_SYN_SCAN** alert.

### Test 3: Trigger Brute-Force Alert
Try SSH with wrong passwords multiple times:
```bash
for i in {1..10}; do ssh root@192.168.1.100; done
```

You should see **BRUTE_FORCE** alert.

## 6. Enable Email Alerts (Optional)

### Gmail Setup (Recommended for Testing)

1. **Go to**: https://myaccount.google.com/apppasswords
2. **Select**: Mail and Windows/Mac/Linux/iPhone/Android
3. **Copy** the 16-character app password

4. **Set environment variable**:
```bash
# Linux/macOS
export NIDS_EMAIL_PASSWORD="your-16-char-password"

# Windows PowerShell
$env:NIDS_EMAIL_PASSWORD = "your-16-char-password"
```

5. **Update config.yaml**:
```yaml
alerting:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    sender_email: "your-email@gmail.com"
    sender_password: "${NIDS_EMAIL_PASSWORD}"
    recipients:
      - "your-email@gmail.com"
    alert_severity_threshold: "HIGH"
```

6. **Restart NIDS**:
```bash
sudo python main.py
```

Now you'll receive email alerts for HIGH and CRITICAL severity threats!

## 7. Enable Database Logging (Optional)

To persist alerts in a SQLite database:

1. **Update config.yaml**:
```yaml
logging:
  database:
    enabled: true
    type: "sqlite"
    connection:
      sqlite:
        db_path: "./logs/nids.db"
```

2. **Restart NIDS** - database will auto-create

3. **Query alerts**:
```bash
sqlite3 logs/nids.db "SELECT rule_name, severity, src_ip FROM alerts LIMIT 10;"
```

## 8. View Dashboard

See real-time metrics in JSON format:

```bash
python main.py --dashboard
```

Output includes:
- System status and uptime
- Recent and critical alerts
- Top threat actors (source IPs)
- Detection rules status
- Alert timeline graphs

## 9. Export Alerts to CSV

Export for analysis in Excel/Sheets:

```bash
python main.py --export my_alerts.csv
```

Then open `my_alerts.csv` in your spreadsheet application.

## 10. Stop NIDS

```bash
# Press Ctrl+C in the terminal
^C
[*] Shutting down NIDS...
[+] NIDS shutdown complete
```

---

## Common Commands Reference

```bash
# Run normally
sudo python main.py

# Run with custom config
sudo python main.py --config custom_config.yaml

# Show dashboard (one-time)
python main.py --dashboard

# Export alerts to CSV
python main.py --export alerts.csv

# View recent logs
tail -f logs/nids_alerts.json

# View alerts database
sqlite3 logs/nids.db "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 20;"
```

## Troubleshooting

### Problem: "Permission denied"
**Solution**: Run with `sudo` (Linux/macOS) or admin PowerShell (Windows)

### Problem: "Scapy not found"
**Solution**: Install dependencies:
```bash
pip install scapy pyyaml
```

### Problem: No packets being captured
**Solution**: Check network interface:
```bash
# List interfaces
ip link show (Linux)
ifconfig (macOS)
ipconfig (Windows)

# Capture on specific interface
# Edit config.yaml:
sniffer:
  interfaces: ["eth0"]  # or your interface
```

### Problem: No alerts even with test traffic
**Solution**: Check configuration thresholds are not too high:
```yaml
detection:
  icmp_flood:
    threshold: 20    # Lower for testing
    time_window: 10
```

---

## Next Steps

1. **Review logs**: `cat logs/nids_alerts.json | jq .`
2. **Analyze statistics**: `python main.py --dashboard | jq .top_threats`
3. **Customize rules**: Edit `config/config.yaml` thresholds
4. **Enable all features**: Follow guides above for email and database
5. **Integrate with monitoring**: Use JSON output in Grafana/ELK
6. **Deploy to production**: Set up as systemd service or Windows service

## Help & Support

- **Read full docs**: See `README.md`
- **Check config**: `config/config.yaml` has all options documented
- **View code**: Each Python module has detailed docstrings
- **Troubleshooting**: See README.md Troubleshooting section

**Happy intrusion detection!** 🛡️
