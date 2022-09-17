#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import copy
import digest_controller
import _thread
import threading
from threading import Thread
from time import sleep
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_p4runtime_API import SimpleSwitchP4RuntimeAPI
import networkx as nx

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2
ECMP_BASE = 1
ECMP_MAX = 10
BANDWIDTH = {"1-2": 3.75, "1-3": 2.5, "2-3": 1.25, "2-4": 2.5, "3-4": 3.75, "2-1": 3.75, "3-1": 2.5, "3-2": 1.25, "4-2": 2.5, "4-3": 3.75}

controllers = []
s = [1,1,2,2,3]
t = [2,3,3,4,4]
# ip:node
ip_address = {"10.0.0.1": 1, "10.0.0.2": 4}
#security value of nodes
security = {"2":1.25, "3":3.75}
entry_handle={}


nodes = 4

switches = [0]
digest_controllers = []



def modifyDesignateRules(controller, entry_handle, out_port
                        ):
    
        #print("Installed Designated dstAddr rule on %s" % controller)
        
 
    entry_handle = controller.table_modify(
    "MyIngress.ecmp_group", 
    "MyIngress.set_designate_nhop",       
    str(entry_handle),
    [str(out_port)])
        
        
    return entry_handle



#set all links capacity to 'bandwidth'
def setLinkCapacityAll(G, bandwidth):   
    for tup in G.edges:
        G.edges[tup[0],tup[1]]["capacity"]=bandwidth
        
#update link Capacity in G , capacity = current_detect + last_loop_capacity
def updateLinkCapacity(G, detect):       
    #for tup in G.edges:
    #    G.edges[tup[0],tup[1]]["capacity"]=detect[str(tup[0]) + '-' + str(tup[1])]
    setLinkCapacity(G, detect)
    
    #
    #for key in history.keys():
    #    src,dst = key.split("-")
    #    G.edges[src,dst]["capacity"] += (history[key] - detect[key])
            
    return G
#add security value(translate node capacity to edge capacity for MaxMinFlow Algorithm)
#params security --> security value of nodes which is defined in global variables

       
        
def main():

    for i in range(1, nodes+1):
        switches.append(SimpleSwitchThriftAPI(9089+i))
        
    for i in range(0, nodes):    
        digest_controllers.append(digest_controller.DigestController("s{}".format(i + 1), 9090 + i))
        threading.Thread(target = digest_controllers[i].run_digest_loop).start()
        
         
    while True:

    
        #print(G.degree[16])
    
    
    
    
    
    
   

    


if __name__ == '__main__':
    main()
