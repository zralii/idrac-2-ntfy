![img1](/img/ntfy_message.PNG)

> **Note:** This project was developed with AI assistance.

# idrac-2-ntfy

Get instant push notifications from your Dell iDRAC server alerts.

## What it does

Listens for SNMP traps from Dell iDRAC and forwards them as notifications to [ntfy](https://ntfy.sh). Get alerts for hardware issues like temperature warnings, fan failures, power supply problems, disk failures, and more - directly to your phone or desktop.

```
iDRAC → SNMP trap (UDP 162) → Container → ntfy → Your Phone
```

## Quick Start

**1. Create `.env` file:**

```bash
NTFY_URL=https://ntfy.sh/your-topic-name
NTFY_TOKEN=your_bearer_token
SNMP_COMMUNITY=public
SNMP_LISTEN_ADDRESS=0.0.0.0
SNMP_LISTEN_PORT=162
IDRAC_LABEL=iDRAC
LOG_LEVEL=INFO
```

**2. Run with Docker:**

```bash
docker-compose up -d
```

**3. Configure iDRAC:**

In your iDRAC web interface:
- Go to **iDRAC Settings → Network → SNMP**
- Enable SNMP traps
- Add trap destination: `<your-server-ip>:162`
- Set community string: `public`
- Send a test trap to verify

## Alert Severity

iDRAC alerts are automatically mapped to ntfy priorities:

- **Critical/Non-Recoverable** → 🚨 urgent
- **Warning** → ⚠️ high  
- **OK** → ✅ default
- **Unknown** → ❓ default

## Configuration Options

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NTFY_URL` | **yes** | - | Full ntfy URL with topic (e.g., `https://ntfy.sh/idrac`) |
| `NTFY_TOKEN` | **yes** | - | Bearer token for authentication |
| `SNMP_COMMUNITY` | no | `public` | Must match iDRAC setting |
| `SNMP_LISTEN_ADDRESS` | no | `0.0.0.0` | Listen on all interfaces |
| `SNMP_LISTEN_PORT` | no | `162` | Standard SNMP trap port |
| `IDRAC_LABEL` | no | `iDRAC` | Server name in notifications |
| `LOG_LEVEL` | no | `INFO` | DEBUG, INFO, WARNING, ERROR |

## Supported Alerts

- Temperature warnings/critical
- Fan failures
- Power supply issues
- Memory errors
- Storage/disk failures
- CPU/processor problems
- Battery warnings
- Network issues
- RAID controller alerts
- System events

## Testing

Send a test SNMP trap locally:

```bash
snmptrap -v 2c -c public localhost:162 '' \
  1.3.6.1.4.1.674.10892.5 \
  1.3.6.1.4.1.674.10892.5.4.300.1.6 s "Test Alert" \
  1.3.6.1.4.1.674.10892.5.4.300.1.8 i 3
```

Check logs:
```bash
docker logs idrac-2-ntfy
```

## Running Without Docker

```bash
pip install -r requirements.txt
export NTFY_URL=https://ntfy.sh/your-topic
export NTFY_TOKEN=your_token
sudo python trap_receiver.py  # Port 162 requires root
```

## License

MIT
