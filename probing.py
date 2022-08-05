from scapy.all import *

UsableNeighbors = []


def ICMP(dstip, num = 100, iface):
    #totallen = num + 42
    load = bytes('test', 'utf-8').zfill(num)
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst=dstip,ttl=2, flags = 2)/ICMP()/load
    ans, unans = srp(pkt, iface='h1-eth0', timeout = 1)
    if len(ans) == 0:
        #没有回应
        return False
    else:
        for snd, rcv in ans:
            if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
                if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                    if rcv.sprint(r"%ICMP.type%") == "echo-reply":
                        return True
            #if rcv.sprint(r"%ICMP.type%") == "time-exceeded":
            #    return False
        return False


def ProbeSingleNeighbor(pkt):
    ans, unans = srp(pkt, iface='h1-eth0', timeout = 1)
    if len(ans) == 0:
        #没有回应
        return False
    else:
        for snd, rcv in ans:
            if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
                if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                    if rcv.sprintf(r"%ICMP.type%") == "echo-reply":
                        return rcv.sprintf(r"%IP.src%")#, rcv.sprintf(r"%Ether.src%")
        return False

def BrouteForce(subnet):
    #example subnet = "10.0.0.1/24"
    ips = IP(dst = subnet)

def ProbeLiveNeighbors(subnet):
    ips = IP(dst = subnet, ttl = 2)
    for ip in ips:
        pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/ip/ICMP()
        ans = ProbeSingleNeighbor(pkt)
        if ans:
            UsableNeighbors.append(ans)

