import scapy.all as scapy
import time
import subprocess
import datetime

NETWORK = "192.168.1.0/24"
INTERVAL = 15  # seconds
dictionary = {
    '52:52:96:d9:12:a4':'Samsung S20 5G',
    '98:8b:0a:b5:c3:85':'CCTV',
    '58:2f:40:79:5e:ec':'Nintendo Switch',
    '58:82:a8:13:28:67':'Xbox One',
    '5c:96:56:2e:c5:cd':'Spencer PS4',
    'd0:d7:83:7f:b8:14':'Huawei P20',
    'd0:d7:83:cb:a1:b6':'Huawei P20',
    'f4:5c:89:ad:ba:fb':'MacBook Pro - Work',
    '02:84:48:33:a4:2a':'Galaxy Tab A',
    'dc:a2:66:48:33:a4:2a':'Laptop Windows',
    'e8:d8:19:2e:ca:93':'Luke PS4',
    'b8:27:eb:c7:81:0c':'Raspberry Pi Zero',
}

def log(device, status):
    with open('logs/log.txt', 'a') as f:
        f.write(f'[{datetime.datetime.now()}] {status} - {device}\n')


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
        device = dictionary[host] if host in dictionary else 'unknown device'
        if action == 'connected':
            log(device, 'CONNECTED')
        else:
            log(device, 'DISCONNECTED')

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