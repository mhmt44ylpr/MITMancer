# -*- coding: utf-8 -*-

import scapy.all as scapy
from scapy.layers.inet import TCP
from scapy.packet import Raw
from optparse import OptionParser
from colorama import Fore, init

init(autoreset=True)

class ListenerTarget:
    def __init__(self):
        self.interface = None
        self.get_user_input()
        print(Fore.GREEN + "[-->] Tarama başlatılıyor...")

    def get_user_input(self):
        parser = OptionParser()
        parser.add_option('-i', '--interface', dest='interface', help='Interface seçin (örnek: eth0, wlan0)')
        (options, arguments) = parser.parse_args()

        if not options.interface:
            parser.error("[-] Lütfen bir interface belirtin. --interface veya -i ile")
        self.interface = options.interface

    def listening_packets(self):
        scapy.sniff(iface=self.interface, store=False, prn=self.packet_analy)

    def packet_analy(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                if "HTTP" in payload or "Host:" in payload:
                    print(Fore.YELLOW + "[+] HTTP Paket:")
                    print(Fore.CYAN + payload)
            except Exception as e:
                pass

if __name__ == '__main__':
    listener = ListenerTarget()
    listener.listening_packets()

