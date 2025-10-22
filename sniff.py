import argparse
from scapy.all import sniff, Ether, IP, TCP, UDP, wrpcap
from datetime import datetime

def format_payload(payload, length=16):
    raw_bytes = bytes(payload)[:length]
    hex_part = ' '.join(f"{b:02x}" for b in raw_bytes)
    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes)
    return f"{hex_part} | {ascii_part}"

def print_packet(packet, verbose=False):
    ts = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    iface = packet.sniffed_on if hasattr(packet, 'sniffed_on') else 'unknown'
    length = len(packet)
    proto = None
    src = dst = sport = dport = '-'

    if IP in packet:
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        proto = {6: 'TCP', 17: 'UDP'}.get(ip.proto, str(ip.proto))

    if TCP in packet:
        tcp = packet[TCP]
        sport = tcp.sport
        dport = tcp.dport
    elif UDP in packet:
        udp = packet[UDP]
        sport = udp.sport
        dport = udp.dport

    payload_preview = format_payload(packet.payload)

    if proto == 'TCP':
        color = '\033[94m'
    elif proto == 'UDP':
        color = '\033[92m'
    else:
        color = '\033[0m'

    reset = '\033[0m'
    output = (f"{color}{ts} | {iface} | {src}:{sport} -> {dst}:{dport} | {proto} | "
              f"len={length} | {payload_preview}{reset}")
    print(output)
    if verbose:
        print(packet.show(dump=True))

def log_packet(packet, log_path):
    ts = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    iface = packet.sniffed_on if hasattr(packet, 'sniffed_on') else 'unknown'
    length = len(packet)
    proto = None
    src = dst = sport = dport = '-'

    if IP in packet:
        ip = packet[IP]
        src = ip.src
        dst = ip.dst
        proto = {6: 'TCP', 17: 'UDP'}.get(ip.proto, str(ip.proto))

    if TCP in packet:
        tcp = packet[TCP]
        sport = tcp.sport
        dport = tcp.dport
    elif UDP in packet:
        udp = packet[UDP]
        sport = udp.sport
        dport = udp.dport

    payload_preview = format_payload(packet.payload)
    with open(log_path, "a") as logf:
        logf.write(f"{ts} | {iface} | {src}:{sport} -> {dst}:{dport} | {proto} | len={length} | {payload_preview}\n")

def packet_callback_factory(packets, log_path, verbose):
    def packet_callback(packet):
        packets.append(packet)
        print_packet(packet, verbose)
        log_packet(packet, log_path)
    return packet_callback

def main():
    parser = argparse.ArgumentParser(
        description="Simple Scapy packet sniffer",
        epilog="Examples of valid BPF filters:\n"
               "  tcp port 80      # HTTP traffic\n"
               "  udp              # All UDP packets\n"
               "  port 53          # DNS traffic\n"
               "  host 192.168.0.1 # Traffic to/from specific host\n"
               "  tcp or udp       # All TCP and UDP packets"
    )
    parser.add_argument("-i", "--iface", help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g. 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=5, help="Number of packets to capture")
    parser.add_argument("-o", "--output", default="packets.pcap", help="Path to save pcap file")
    parser.add_argument("-l", "--log", default="packets.log", help="Path to save log file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose packet info")
    args = parser.parse_args()

    packets = []
    callback = packet_callback_factory(packets, args.log, args.verbose)

    sniff_kwargs = {
        "prn": callback,
        "count": args.count,
        "iface": args.iface
    }
    if args.filter:
        sniff_kwargs["filter"] = args.filter

    sniff(**sniff_kwargs)
    wrpcap(args.output, packets)

if __name__ == "__main__":
    main()
