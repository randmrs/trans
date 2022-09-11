from scapy.all import *
from time import sleep
from datetime import datetime
import threading



source_macs_pool = []
num_rule = 10000

packets = []

hard_timeout = 200
idle_timeout = 20

def rand_macs(num_rules):
    for i in range(num_rules):
        print(i)
        smac_rand = RandMAC("*:*:*:*:*:*")
        if smac_rand not in source_macs_pool:
            source_macs_pool.append(smac_rand)

def send_forge_packet(src_mac, port):
    pkt = Ether(src=src_mac, dst='00:00:00:00:00:01') / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(sport=port,dport=8080) / str(port)
    sendp(pkt, iface='h1-eth0')

def sendpacket(begin, end):
    while True:
        for pkt in packets[begin:end]:
            sendp(pkt, iface='h1-eth0')
            sleep(0.016)



def main():
    #with open('/home/kdz/data/random_macs.txt', 'r') as f:
     #   macs = f.readlines()
    #f.close()
    #for mac in macs:
     #   #print(mac)
     #   source_macs_pool.append(mac[:-1])
    i = 0

    with open('/home/kdz/data/random_macs.txt', 'r') as f:
        macs = f.readlines()
    f.close()
    for mac in macs:
        source_macs_pool.append(mac[:-1])
        

    
    for i in range(len(source_macs_pool)):
        pkt = Ether(src=source_macs_pool[i], dst='00:00:00:00:00:02') / IP(src='10.0.0.1', dst='10.0.0.2') / ICMP()
        packets.append(pkt)
    
    #t = 0
    t1 = threading.Thread(target=sendpacket, args=(0, 600, ))
    
    t2 = threading.Thread(target=sendpacket, args=(601, 1200, ))
    t3 = threading.Thread(target=sendpacket, args=(1201, 1800, ))
    t1.start()
    sleep(25)
    t2.start()
    sleep(25)
    t3.start()

if __name__ == '__main__':
    main()


