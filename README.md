# panmanager

Author: Simon Taylor
Current Version: 1.0

Description:
   - Panmanager is a CLI API tool for Palo Alto firewalls/Panorama object/rule/route management. A pre-defined CSV file format is used as a translation layer for ease of conversion between systems or management of a single system.

Current abilities:
   - print all objects and Security/NAT rules from a Palo Alto firewall or Panorama Device Group to screen
   - write all objects and Security/NAT rules from a Palo Alto firewall or Panorama Device Group to Standard CSV format
   - create/edit/delete AddressObjects from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete AddressGroups from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete ApplicationObjects from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete ApplicationGroups from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete ServiceObjects from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete ServiceGroups from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete Tags from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete Dynamic IPs from a Palo Alto firewall
   - create/edit/delete StaticRoutes from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete SecurityRules from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete NatRules from a Palo Alto firewall or Panorama Device Group
   - emails log output file to recipients

Future abilities:
   - create/edit/delete Vsys from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete VirtualRouters from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete Interfaces from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete SecurityProfileGroups from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete ApplicationFilters from a Palo Alto firewall or Panorama Device Group
   - output support for condition where total registered-ips is >500

Cannot support:
   - Pandevice does not return "dependent apps" for an ApplicationObject so cannot check for dependent apps in this script

Dependencies:
   - Pandevice, pandevice==0.9.1
   - More-itertools, more-itertools==7.0.0
  
PAN-OS Versions tested:
   - Panorama, 7.1.11, 8.0.5
   - Firewall, 7.1.21, 8.0.5


CSV Examples:
   - See samples.csv for some example csv lines.

Operation:

Run the following to collect a CSV file from an existing device and examine contents in Excel:
   
    Collect Panorama Objects to file:
    ./panmanager.py -d <panorama.fqdn> -u admin -p *** -o

    Collect all Device Group Objects to file:
    ./panmanager.py -d <panorama.fqdn> -u admin -p *** -o –l ALL

    Collect Specific Device Group Objects to file:
    ./panmanager.py -d <panorama.fqdn> -u admin -p *** -o –l <device_group_name>

    Collect Firewall Objects to file:
    ./panmanager.py -d <firewall.fqdn> -u admin -p *** -o –l ALL

    Create Firewall Shared Objects with checks:
    ./panmanager.py -d <firewall.fqdn> -u admin -p *** -f csv-standard.csv

    Create Firewall Shared Objects without checks:
    ./panmanager.py -d <firewall.fqdn> -u admin -p *** -f csv-standard.csv --no-checks

    Create Firewall ALL Objects with checks:
    ./panmanager.py -d <firewall.fqdn> -u admin -p *** -f csv-standard.csv –l ALL

    Create Specific Firewall VSYS Objects with checks:
    ./panmanager.py -d <firewall.fqdn> -u admin -p *** -f csv-standard.csv –l vsys1

    Create Specific Firewall VSYS DIPs without checks or locks:
    ./panmanager.py -d <firewall.fqdn> -u admin -p *** -f csv-standard.csv –l vsys2 -–no-checks -–no-locks
