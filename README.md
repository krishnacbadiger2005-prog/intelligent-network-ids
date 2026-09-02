# NetSniff IDS

NetSniff is a Wireshark-style live packet analyzer and lightweight IDS. It uses Python, Scapy, Npcap, REST APIs, and WebSocket live updates.

## Project Structure

```text
netsniff.py                 Main launcher
netsniff_app/
  analyzer.py               Sessions, IDS detection, alerts, live events
  capture.py                Scapy/Npcap live capture
  models.py                 Packet data model
  parsers.py                HTTP, DNS, TLS metadata parsing
  rules.py                  YAML-style rule loading/saving
  server.py                 HTTP API, static UI, WebSocket/SSE
  websocket.py              Lightweight WebSocket framing
  utils.py                  Time, entropy, matching helpers
static/
  index.html                User interface
  styles.css                Dark Wireshark-like styling
  app.js                    Live UI behavior and filters
rules.yaml                  Detection rules
requirements.txt           Python dependency list
```

## Install Requirements

1. Install Python 3.13.x.
2. Install Npcap from [npcap.com](https://npcap.com/).
3. During Npcap setup, enable WinPcap-compatible mode.
4. Open PowerShell as Administrator.
5. Run:

```powershell
cd "C:\Users\Krishna Badiger\OneDrive\Desktop\NETSNIFF"
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run Live Capture

Run PowerShell as Administrator, then:

```powershell
cd "C:\Users\Krishna Badiger\OneDrive\Desktop\NETSNIFF"
.\.venv\Scripts\Activate.ps1
python netsniff.py
```

Open this URL:

```text
http://127.0.0.1:8000
```

Click `Start`. Every run clears old packets automatically, so the dashboard contains only newly captured packets.

## Useful Modes

Live Npcap mode:

```powershell
python netsniff.py
```

## API

- `GET /packets`
- `GET /sessions`
- `GET /alerts`
- `GET /statistics`
- `GET /dns`
- `GET /http`
- `GET /tls`
- `GET /rules`
- `POST /capture/start`
- `POST /capture/stop`
- `POST /rules`
- `DELETE /clear`

## Notes

Live packet capture on Windows needs both Npcap and Administrator permission. If Scapy is missing, install it with `python -m pip install scapy`.
