from monitor import start_sniffing
from ids import analyze_packet


def main():
    print("[*] Smart Locker IDS/IPS запущена")
    start_sniffing(analyze_packet)


if __name__ == "__main__":
    main()
