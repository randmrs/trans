from scapy.all import *


def ICMP(dstip):
    
    load = bytes('test', 'utf-8').zfill(500)
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst=dstip,ttl=1)/ICMP()/load
    ans, unans = srp(pkt, iface='h1-eth0', timeout = 1)
    if len(ans) == 0:
        #没有回应
        return False
    else:
        for an in ans:
            for snd, rcv in an:
                if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
                    if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                        if rcv.sprint(r"%ICMP.type%") == "echo-reply":
                            return True
                #if rcv.sprint(r"%ICMP.type%") == "time-exceeded":
                #    return False
        return False




def BrouteForce(subnet):
    #example subnet = "10.0.0.1/24"
    ips = IP(dst = subnet)
