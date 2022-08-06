from scapy.all import *

UsableNeighbors = []
EstimatedMTU = []


def icmp(dstip,  iface, num = 100):
    #totallen = num + 42
    load = bytes('test', 'utf-8').zfill(num)
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst=dstip,ttl=2, flags = 2)/ICMP()/load
    ans, unans = srp(pkt, iface=iface, timeout = 1)
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


#only for porbe live neighbors
def ProbeLiveNeighbors_ARP(subnet, iface):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = subnet)
    ans, unans = srp(pkt, iface = iface, timeout = 1)
    if len(ans) == 0:
        return False
    else:
        for snd, rcv in ans:
            UsableNeighbors.append(rcv[ARP].psrc)
        return True


def ProbeSingleNeighbor_ICMP(pkt, iface):
    ans, unans = srp(pkt, iface=iface, timeout = 0.06)
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


def ProbeLiveNeighbors_ICMP(subnet, iface):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst = subnet, ttl = 2)/ICMP()
    ans, unans = srp(pkt, iface = iface, timeout = 0.6)
    for snd, rcv in ans:
        if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
            if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                if rcv.sprintf(r"%ICMP.type%") == "echo-reply":
                    if rcv.sprintf(r"%IP.src%") not in UsableNeighbors:
                        UsableNeighbors.append(rcv.sprintf(r"%IP.src%"))#, rcv.sprintf(r"%Ether.src%")

    
    #ips = IP(dst = subnet, ttl = 2)
    #for ip in ips:
    #    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/ip/ICMP()
    #    ans = ProbeSingleNeighbor_ICMP(pkt, iface)
    #    if ans:
    #        UsableNeighbors.append(ans)


def ProbeLiveNeighbors_TCP_SYN(subnet, iface):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst = subnet, ttl = 2)/TCP(dport = 80, flag = 'S')
    ans, unans = srp(pkt, iface = iface, timeout = 0.6)
    for snd, rcv in ans:
        if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
            if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                if rcv.sprintf(r"%IP.src%") not in UsableNeighbors:
                    UsableNeighbors.append(rcv.sprintf(r"%IP.src%"))#, rcv.sprintf(r"%Ether.src%")


def ProbeLiveNeighbors_TCP_ACK(subnet, iface):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst = subnet, ttl = 2)/TCP(dport = 80, flag = 'A')
    ans, unans = srp(pkt, iface = iface, timeout = 0.6)
    for snd, rcv in ans:
        if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
            if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                if rcv.sprintf(r"%IP.src%") not in UsableNeighbors:
                    UsableNeighbors.append(rcv.sprintf(r"%IP.src%"))#, rcv.sprintf(r"%Ether.src%")



def BrouteForce(subnet, iface):
    #the error between real MTU and estimated MTU
    margin = 4
    
    low = 1457
    high = 2*low
    for ip in UsableNeighbors:
        while True:
            if (high - low) <= margin:
                EstimatedMTU.append(low)
                break
            if icmp(ip, iface, num = high):
                low = high
                high = 2 * high
            elif icmp(ip, iface, num = int((high + low)/2) + 1):
                low = int((high + low)/2) + 1
            else:
                high = int((high + low)/2) + 1


