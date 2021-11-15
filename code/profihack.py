from scapy.all import *
from pnio import ProfinetIO
from pnio_dcp import *
from threading import Thread
import time

SEND = False

REQUEST = 0
RESPONSE = 1

IFACE="enp0s25"
DCP_IDENTIFY_REQUEST_PERIOD=6 # sec

PNIO_MULTICAST = "01:0e:cf:00:00:00"
SNIFF_FILTER_PNIO_MULTICAST = "ether dst 01:0e:cf:00:00:00"
SNIFF_FILTER_PNIO = "ether proto 0x8892 or 0x8100"

DCP_GET_SET_FRAME_ID = 0xFEFD
DCP_IDENTIFY_REQUEST_FRAME_ID = 0xFEFE
DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF



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
known_hosts = {}

def check_dcp_packet(pkt):

    try:
        pkt[ProfinetIO].frameID
    except:
        return

    if (pkt[ProfinetIO].frameID == DCP_IDENTIFY_RESPONSE_FRAME_ID):
        tmp_dict = {}

        ## if there is a name of station block
        try:
            tmp_dict["name_of_station"] = pkt[DCPNameOfStationBlock].name_of_station
        except:
            pass

        try:
            tmp_dict["vendor_id"] = pkt[DCPDeviceIDBlock].vendor_id
            tmp_dict["device_id"] = pkt[DCPDeviceIDBlock].device_id
        except:
            pass

        try:
            tmp_dict["device_vendor"] = pkt[DCPManufacturerSpecificBlock].device_vendor_value
        except:
            pass

        try:
            tmp_dict["ip"] = pkt[DCPIPBlock].ip
            tmp_dict["netmask"] = pkt[DCPIPBlock].netmask
            tmp_dict["gateway"] = pkt[DCPIPBlock].gateway
        except:
            pass

        known_hosts[pkt.src] = tmp_dict
        print(known_hosts)


def periodically_send_dcp_identify_requests():
    while 1:
        print("send DCP_IDENTIFY_REQUEST to", str(IFACE))
        t=dcp_identify_all_request()
        sendp(t, iface=IFACE)
        time.sleep(DCP_IDENTIFY_REQUEST_PERIOD)


def sniff_dcp_responses():
    print("start sniffer")
    sniff(prn=check_dcp_packet, filter=SNIFF_FILTER_PNIO)


def dcp_identify_all_request():
    return Ether(dst=PNIO_MULTICAST)/ProfinetIO(frameID=DCP_IDENTIFY_REQUEST_FRAME_ID)/ProfinetDCP(service_id=5, service_type=REQUEST, option=255, sub_option=255, dcp_data_length=4)


def dcp_set_name_of_station_request(mac, name):

    if not name:
        name = "mallory"

    dcp_block_len = len(name) + 2

    dcp_data_len = dcp_block_len + 4

    if dcp_block_len % 2 != 0:
        dcp_data_len +=1

############ ET200SP
p = dcp_set_name_of_station_request("ac:64:17:21:35:cf", "et200sp")
sendp(p, iface="enp0s25")
