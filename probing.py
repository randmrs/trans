from scapy.all import *

UsableNeighbors = []
EstimatedMTU = []


def ProbeMTU_ICMP(dstip,  iface, num = 100, ttl):
    #totallen = num + 42
    load = bytes('test', 'utf-8').zfill(num)
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst=dstip,ttl=ttl, flags = 2)/ICMP()/load
    ans, unans = srp(pkt, iface=iface, timeout = 1)
    if len(ans) == 0:
        #没有回应
        return False
    else:
        for snd, rcv in ans:
            if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
                if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                    if rcv.sprintf(r"%ICMP.type%") == "echo-reply":
                        return True
            #if rcv.sprint(r"%ICMP.type%") == "time-exceeded":
            #    return False
        return False


def ProbeMTU_TCP_SYN(dstip,  iface, num = 100, ttl):
    #totallen = num + 54
    load = bytes('test', 'utf-8').zfill(num)
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst=dstip,ttl=ttl, flags = 2)/TCP(dport = 80, flags = 'S')/load
    ans, unans = srp(pkt, iface=iface, timeout = 1)
    if len(ans) == 0:
        #没有回应
        return False
    else:
        for snd, rcv in ans:
            if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
                if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                    return True
            #if rcv.sprint(r"%ICMP.type%") == "time-exceeded":
            #    return False
        return False


def ProbeMTU_TCP_ACK(dstip,  iface, num = 100, ttl):
    #totallen = num + 54
    load = bytes('test', 'utf-8').zfill(num)
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst=dstip,ttl=ttl, flags = 2)/TCP(dport = 80, flags = 'A')/load
    ans, unans = srp(pkt, iface=iface, timeout = 1)
    if len(ans) == 0:
        #没有回应
        return False
    else:
        for snd, rcv in ans:
            if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
                if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
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
            if rcv[ARP].psrc not in UsableNeighbors:
                UsableNeighbors.append(rcv[ARP].psrc)
        return True


def ProbeSingleNeighbor_ICMP(pkt, iface):
    ans, unans = srp(pkt, iface=iface, timeout = 0.06)
    if len(ans) == 0:
        return False
    else:
        for snd, rcv in ans:
            if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
                if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                    if rcv.sprintf(r"%ICMP.type%") == "echo-reply":
                        return rcv.sprintf(r"%IP.src%")#, rcv.sprintf(r"%Ether.src%")
        return False


def ProbeLiveNeighbors_ICMP(subnet, iface, ttl):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst = subnet, ttl = ttl)/ICMP()
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


def ProbeLiveNeighbors_TCP_SYN(subnet, iface, ttl):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst = subnet, ttl = ttl)/TCP(dport = 80, flags = 'S')
    ans, unans = srp(pkt, iface = iface, timeout = 0.6)
    for snd, rcv in ans:
        if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
            if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                if rcv.sprintf(r"%IP.src%") not in UsableNeighbors:
                    UsableNeighbors.append(rcv.sprintf(r"%IP.src%"))#, rcv.sprintf(r"%Ether.src%")


def ProbeLiveNeighbors_TCP_ACK(subnet, iface, ttl):
    pkt = Ether(dst = "ff:ff:ff:ff:ff:ff")/IP(dst = subnet, ttl = ttl)/TCP(dport = 80, flags = 'A')
    ans, unans = srp(pkt, iface = iface, timeout = 0.6)
    for snd, rcv in ans:
        if rcv.sprintf(r"%IP.src%") == snd.sprintf(r"%IP.dst%"):
            if rcv.sprintf(r"%IP.dst%") == snd.sprintf(r"%IP.src%"):
                if rcv.sprintf(r"%IP.src%") not in UsableNeighbors:
                    UsableNeighbors.append(rcv.sprintf(r"%IP.src%"))#, rcv.sprintf(r"%Ether.src%")



def BrouteForce(subnet, iface, ttl):
    #the error between real MTU and estimated MTU
    margin = 4
    
    #icmp
    low = 1300
    high = 2*low
    
    for ip in UsableNeighbors:
        n = 0
        if ip == "NEW":
            EstimatedMTU.append("NEW")
            continue
        while True:
            n += 1
            if n > 100:
                break
            if (high - low) <= margin:
                EstimatedMTU.append(low + 42)
                break
            if ProbeMTU_ICMP(ip, iface, num = high, ttl = ttl):
                low = high
                high = 2 * high
            elif ProbeMTU_ICMP(ip, iface, num = int((high + low)/2) + 1, ttl = ttl):
                low = int((high + low)/2) + 1
            else:
                high = int((high + low)/2) + 1
    
    #tcp-syn
    low = 1300
    high = 2*low
    for ip in UsableNeighbors:
        n = 0
        if ip == "NEW":
            EstimatedMTU.append("NEW")
            continue
        while True:
            n += 1
            if n > 100:
                break
            if (high - low) <= margin:
                EstimatedMTU.append(low + 54)
                break
            if ProbeMTU_TCP_SYN(ip, iface, num = high, ttl = ttl):
                low = high
                high = 2 * high
            elif ProbeMTU_TCP_SYN(ip, iface, num = int((high + low)/2) + 1, ttl = ttl):
                low = int((high + low)/2) + 1
            else:
                high = int((high + low)/2) + 1


    #tcp-ack
    low = 1300
    high = 2*low
    for ip in UsableNeighbors:
        n = 0
        if ip == "NEW":
            EstimatedMTU.append("NEW")
            continue
        while True:
            n += 1
            if n > 100:
                break
            if (high - low) <= margin:
                EstimatedMTU.append(low + 54)
                break
            if ProbeMTU_TCP_ACK(ip, iface, num = high, ttl = ttl):
                low = high
                high = 2 * high
            elif ProbeMTU_TCP_ACK(ip, iface, num = int((high + low)/2) + 1, ttl = ttl):
                low = int((high + low)/2) + 1
            else:
                high = int((high + low)/2) + 1



def start(subnet, iface, ttl):
    ProbeLiveNeighbors_ICMP(subnet,iface, ttl)
    ProbeLiveNeighbors_TCP_ACK(subnet, iface, ttl)
    ProbeLiveNeighbors_TCP_SYN(subnet, iface, ttl)


def main():
    subnet = "10.0.2.2/22"
    iface = "eth0"
    ttl = 1
    while len(UsableNeighbors) == 0:
        print(ttl)
        start(subnet, iface, ttl)
        ttl += 1
    BrouteForce(subnet, iface)
    for MTU in EstimatedMTU:
        print(MTU)