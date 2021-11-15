#!/usr/bin/env python3
from scapy.all import *
import json
from configmgr import ConfigMgr
from threading import Thread
import time
### take pnio_dcp contrib from scapy
# NOTE: using the official contrib file leads to no result for the identify script -> so just use the local one
# from scapy.contrib.pnio import *
# from scapy.contrib.pnio_dcp import *
### take local ones
from pnio import ProfinetIO
from pnio_dcp import *

DCP_GET_SET_FRAME_ID = 0xFEFD
DCP_IDENTIFY_REQUEST_FRAME_ID = 0xFEFE
DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF

DEBUG = False

class DCPIdentify():

    REQUEST = 0
    RESPONSE = 1

    def __init__(self):
        ### this is a json-style 'database' with all data for all found stations
        ### identifier should be mac addr
        ##  {
        #       mac_addr : {
        #           device_vendor : "SIMATIC-PC",           DCPManufacturerSpecificBlock    -> device_vendor_value
        #           vendor_id : "0x2a"                      DCPDeviceIDBlock                -> vendor_id
        #           device_id : "0x202"                     DCPDeviceIDBlock                -> device_id
        #           name_of_station : "hase",               DCPNameOfStationBlock           -> name_of_station
        #           ip              : "192.168.1.100"       DCPIPBlock                      -> ip
        #           netmask         : "255.255.255.0"       DCPIPBlock                      -> netmask
        #           gateway         : "0.0.0.0"             DCPIPBlock                      -> gateway
        #       }
        #   }
        self.known_hosts = {}

        cm = ConfigMgr()

        self.IFACE = cm.getValue("Attacker", "iface", "enp0s25")
        self.SNIFF_TIMEOUT = int(cm.getValue("Attacker", "identify_timeout", 3))
        self.PNIO_MULTICAST = "01:0e:cf:00:00:00"
        self.SNIFF_FILTER_PNIO_MULTICAST = "ether dst 01:0e:cf:00:00:00"
        self.SNIFF_FILTER_PNIO = "ether proto 0x8892 or 0x8100"

    def check_dcp_packet(self, pkt):

        if DEBUG:
            pkt.show2()
        try:
            pkt[ProfinetIO].frameID
        except:
            return


        if (pkt[ProfinetIO].frameID == DCP_IDENTIFY_RESPONSE_FRAME_ID):
            tmp_dict = {}

            ## if there is a name of station block
            try:
                tmp_dict["name_of_station"] = str(pkt[DCPNameOfStationBlock].name_of_station)
            except:
                pass

            try:
                tmp_dict["vendor_id"] = str(pkt[DCPDeviceIDBlock].vendor_id)
                try:
                    ## NOTE: Manufacturer ID Table
                    # due to due to legal regulations it is not permitted to publish the vendor list by any means
                    # see: https://www.profibus.com/IM/Man_ID_Table.xml
                    # I provided a dummy pnio_vendrs file in repo
                    import pnio_vendors
                    tmp_dict["vendor_name"] = pnio_vendors.pnio_vendors_dict.get(pkt[DCPDeviceIDBlock].vendor_id)
                except:
                    pass
                tmp_dict["device_id"] = str(pkt[DCPDeviceIDBlock].device_id)
            except:
                pass

            try:
                tmp_dict["device_vendor"] = str(pkt[DCPManufacturerSpecificBlock].device_vendor_value)
            except:
                pass

            try:
                tmp_dict["ip"] = pkt[DCPIPBlock].ip
                tmp_dict["netmask"] = pkt[DCPIPBlock].netmask
                tmp_dict["gateway"] = pkt[DCPIPBlock].gateway
            except:
                pass

            try:
                d = pkt[DCPDeviceRoleBlock].device_role_details
                if d == 0: d = "IO Supervisor"
                elif d == 1: d = "IO Device"
                elif d == 2: d = "IO Controller"

                tmp_dict['device_role'] = d
            except:
                pass

            self.known_hosts[pkt.src] = tmp_dict


    def send_dcp_identify_requests(self):
        print("send DCP_IDENTIFY_REQUEST to", str(self.IFACE))
        t = self.dcp_identify_all_request()
        sendp(t, iface=self.IFACE)

    def sniff_dcp_responses(self):
        print("start sniffer")
        sniff(iface=self.IFACE, prn=self.check_dcp_packet, filter=self.SNIFF_FILTER_PNIO, timeout=self.SNIFF_TIMEOUT)
        self.prettify_print(self.known_hosts)
        return self.known_hosts

    def dcp_identify_all_request(self):
        return Ether(dst=self.PNIO_MULTICAST)/ProfinetIO(frameID=DCP_IDENTIFY_REQUEST_FRAME_ID)/ProfinetDCP(service_id=5, service_type=self.REQUEST, option=255, sub_option=255, dcp_data_length=4)

    def prettify_print(self, res):
        # print(res)
        r = json.dumps(res)
        print(json.dumps(json.loads(r), indent=4, sort_keys=True))


###################

if __name__ == '__main__':
    d = DCPIdentify()
    #### start dcp checker thread
    d.identify_response_thread = Thread(target=d.sniff_dcp_responses)
    d.identify_response_thread.start()

    ## waiting 1 sec
    time.sleep(1)

    d.send_dcp_identify_requests()
