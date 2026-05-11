from logger import log_warning
from config import SYN_THRESHOLD, PORT_SCAN_THRESHOLD
from ips import block_ip

syn_count = {}
port_scan = {}

def analyze_packet(packet):
    src_ip = packet.get("src_ip")

    if not src_ip:
        return

    print(packet)

    # --- SYN Flood ---
    if packet.get("protocol") == "TCP":
        flags = packet.get("flags", "")

        if "S" in flags:
            syn_count[src_ip] = syn_count.get(src_ip, 0) + 1

            if syn_count[src_ip] > SYN_THRESHOLD:
                print(f"[ALERT] SYN Flood от {src_ip}")
                block_ip(src_ip)

    # --- Port Scan ---
    dst_port = packet.get("dst_port")

    if dst_port:
        if src_ip not in port_scan:
            port_scan[src_ip] = set()

        port_scan[src_ip].add(dst_port)

        if len(port_scan[src_ip]) > PORT_SCAN_THRESHOLD:
            print(f"[ALERT] Port scan от {src_ip}")
            block_ip(src_ip)
