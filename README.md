# Sniffer tool

Small Scapy-based packet sniffer. Captures packets, prints human-readable lines, logs to file and saves captures to a pcap.

## Requirements
- Windows or Unix with Python 3.8+
- scapy
- On Windows: install Npcap for L2 capture (https://nmap.org/npcap/)

## Quick setup (PowerShell)
1. Create & activate venv:
    ```powershell
    python -m venv sniff_venv
    .\sniff_venv\Scripts\Activate.ps1
    ```
2. Install dependencies:
    ```powershell
    python -m pip install scapy
    # optional: save deps
    python -m pip freeze > requirements.txt
    ```

## Run
Basic:
```powershell
python sniff.py
```
With options:
```powershell
python sniff.py -i "<interface>" -f "tcp port 80" -c 100 -o capture.pcap -l capture.log -v
```
Options:
- `-i, --iface`  : interface name (optional)
- `-f, --filter` : BPF filter string (optional — if omitted, no filter applied)
- `-c, --count`  : number of packets to capture (default: 5)
- `-o, --output` : pcap output path (default: packets.pcap)
- `-l, --log`    : text log path (default: packets.log)
- `-v, --verbose`: show verbose packet info

The program shows a 3s banner/countdown before capturing.

## BPF examples
- HTTP (port 80): `tcp port 80`
- All TCP/UDP: `tcp or udp`
- DNS: `port 53`
- Host: `host 192.168.0.10`
Note: `http` alone is not a valid BPF expression.

## Output
- pcap saved to `-o` path (open with Wireshark)
- text log saved to `-l` path
- console output is colorized (TCP/UDP)

## Do not commit virtualenv
Add a `.gitignore` entry to avoid pushing `sniff_venv/`. Example:
```
sniff_venv/
__pycache__/
*.py[cod]
.vscode/
.env
```

## Notes
- If you want L2 captures on Windows, install Npcap and run Powershell/terminal as Administrator if required.
- Use a Personal Access Token or SSH key for GitHub pushes.

License: MIT (or choose one)