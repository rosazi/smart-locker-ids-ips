from logger import log_info
import os
from config import ENABLE_IPS, WHITELIST

blocked_ips = set()

def block_ip(ip):
    if not ENABLE_IPS:
        return

    if ip in WHITELIST:
        return

    if ip in blocked_ips:
        return

    print(f"[IPS] Блокировка IP: {ip}")

    os.system(f"iptables -A INPUT -s {ip} -j DROP")

    blocked_ips.add(ip)
