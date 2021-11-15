# DoS Profi

This repo provides the attack scripts that were used in my paper "No Need to Marry to Change Your Name! Attacking Profinet IO Automation Networks Using DCP." at DIMVA 2019

## How does it work?

Profinet ...

## How to Use 

### Configuration

- we provide a sample config names ´default_config.ini´. Please rename this file to `config.ini` and change the parameters so that it fits to your setup (e.g. target MAC address) 

### Topology Exploration

```
> sudo identify.py

start sniffer
send DCP_IDENTIFY_REQUEST to enp2s0
.
Sent 1 packets.
{
    "20:87:56:90:1b:3e": {
        "device_id": "2571",
        "device_role": "IO Device",
        "device_vendor": "b'SCALANCE XC-200'",
        "gateway": "0.0.0.0",
        "ip": "192.168.1.3",
        "name_of_station": "b'mallory'",
        "netmask": "255.255.255.0",
        "vendor_id": "42",
        "vendor_name": "Siemens AG"
    },
    "ac:64:17:21:35:cf": {
        "device_id": "787",
        "device_role": "IO Device",
        "device_vendor": "b'ET200SP'",
        "gateway": "192.168.1.14",
        "ip": "192.168.1.14",
        "name_of_station": "b'et200sp'",
        "netmask": "255.255.255.0",
        "vendor_id": "42",
        "vendor_name": "Siemens AG"
    }
}
```

### Port Stealing

> sudo port_stealing.py

### Reconfiguration Attack

> sudo set_attack.py


### Persisent Denial of Service 

> sudo dcp_identify_name_dos_attack.py




## Reference

You are free to use this code to stress your own hardware or for academic reasons, but please to not shot down any production system!

If you use the code in any way, please cite our DIMVA 2019 **[paper](paper/Mehner2019_No_Need_to_Marry_to_Change_Your_Name_Attacking_Profinet_IO_Automation_Networks_Using_DCP.pdf)**. Here is the bibtex:

Bibtex Entry:

```
@InProceedings{10.1007/978-3-030-22038-9_19,
author="Mehner, Stefan and K{\"o}nig, Hartmut",
editor="Perdisci, Roberto and Maurice, Cl{\'e}mentine and Giacinto, Giorgio and Almgren, Magnus",
title="No Need to Marry to Change Your Name! Attacking Profinet IO Automation Networks Using DCP",
booktitle="Detection of Intrusions and Malware, and Vulnerability Assessment",
year="2019",
publisher="Springer International Publishing",
address="Cham",
pages="396--414"
}
```

