from scapy.all import sniff
from config import INTERFACE


def process_packet(packet, callback):
    packet_info = {}

    if packet.haslayer("IP"):
        packet_info["src_ip"] = packet["IP"].src
        packet_info["dst_ip"] = packet["IP"].dst
        packet_info["protocol"] = "IP"

        if packet.haslayer("TCP"):
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = packet["TCP"].sport
            packet_info["dst_port"] = packet["TCP"].dport
            packet_info["flags"] = str(packet["TCP"].flags)

        elif packet.haslayer("UDP"):
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = packet["UDP"].sport
            packet_info["dst_port"] = packet["UDP"].dport

        elif packet.haslayer("ICMP"):
            packet_info["protocol"] = "ICMP"

        callback(packet_info)


def start_sniffing(callback):
    print("[*] Мониторинг запущен...")
    sniff(
        iface=INTERFACE,
        filter="ip",
        prn=lambda pkt: process_packet(pkt, callback),
        store=False
    )
