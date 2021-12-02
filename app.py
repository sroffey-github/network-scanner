from os import closerange
import scapy.all as scapy
import time, datetime

NETWORK = "192.168.1.0/24"
INTERVAL = 30  # seconds

dictionary = {
    "mac":"name"
}

def log(name, status):
    with open('logs/log.txt', 'a') as f:
        f.write(f'[{datetime.datetime.now()}] {status.upper()}: {name.title()}\n')

def scan(ip):
    macs = set()
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    for host in answered_list:
        if host[1].psrc != "192.168.1.1":
            macs.add(host[1].src)
    return macs

def connection_change(hosts, action):
    if action not in ("connected", "disconnected"):
        raise ValueError(f"Invalid action: {action}")
    for host in hosts:
        if host.upper() in dictionary:
            device = dictionary[host.upper()]
            if action == 'connected':
                log(device, 'connected')
            else:
                log(device, 'disconnected')
        else:
            pass

def main():
    old_macs = scan(NETWORK)
    connection_change(old_macs, "connected")
    while True:
        time.sleep(INTERVAL)
        macs = scan(NETWORK)

        new = macs - old_macs
        connection_change(new, "connected")

        left = old_macs - macs
        connection_change(left, "disconnected")

        old_macs = macs


if __name__ == "__main__":
    main()