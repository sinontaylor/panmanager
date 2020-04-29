# panmanager

Author: Simon Taylor
Current Version: 1.4

Description:
   - Panmanager is a CLI API tool for Palo Alto firewalls/Panorama object/rule/route management. A pre-defined CSV file format is used as a translation layer for ease of conversion between systems or management of a single system.

Current abilities:
   - print all objects and Security/NAT rules from a Palo Alto firewall or Panorama Device Group to screen
   - write all objects and Security/NAT rules from a Palo Alto firewall or Panorama Device Group to Standard CSV format
   - create/edit/delete/rename AddressObjects from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete/rename AddressGroups from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete/rename ApplicationObjects from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete/rename ApplicationGroups from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete/rename ServiceObjects from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete/rename ServiceGroups from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete/rename Tags from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete Dynamic IPs from a Palo Alto firewall
   - create/edit/delete StaticRoutes from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete/rename SecurityRules from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete/rename NatRules from a Palo Alto firewall or Panorama Device Group
   - emails log output file to recipients

Future abilities:
   - create/edit/delete Vsys from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete VirtualRouters from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete Interfaces from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete SecurityProfileGroups from a Palo Alto firewall or Panorama Device Group
   - create/edit/delete ApplicationFilters from a Palo Alto firewall or Panorama Device Group
   - output support for condition where total registered-ips is >500
   - move rules before/after specified rule UUID 

Cannot support:
   - Pandevice does not return "dependent apps" for an ApplicationObject so cannot check for dependent apps in this script

Dependencies:
   - Pandevice, pandevice==0.12.0
   - More-itertools, more-itertools==7.0.0
  
PAN-OS Versions tested:
   - Panorama, 7.1.x, 8.0.x, 8.1.x, 9.0.4
   - Firewall, 7.1.x, 8.0.x, 8.1.x, 9.0.4


CSV Examples:
   - See samples.csv for some example csv lines.

Operation:

   - Run the following to collect a CSV file from an existing device and examine contents in Excel:
   
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
    ./panmanager.py -d <firewall.fqdn> -u admin -p *** -f csv-standard.csv –l vsys
    
    Create Specific Firewall VSYS DIPs without checks or locks:
    ./panmanager.py -d <firewall.fqdn> -u admin -p *** -f csv-standard.csv –l vsys2 -–no-checks -–no-locks

General Rules:

   - Some details concerning the flow inside the tool:

   - The tool contains a lot of error handling since it is designed to be used in Automation. Tip: Check the log file for errors!

   - The tool will email its log file upon completion.

   - The tool will perform the CSV ‘actions’ in a specific order:

	      action_order = ['delete', 'rename', 'create', 'edit', 'addtogroup', 'removefromgroup']

   - For each ‘action’, similarly the objects are updated in a specific order (owing to dependencies):

	      object_order = ['route', 'dip', 'tag', 'address', 'address-group', 'service', 'service-group', 'application',  'application-group', 'security-rules', 'nat-rules', 'deletion' , 'edits', 'add/remove']

   - Owing to dependencies, any ‘shared’ objects are updated first.

   - Groups will not be left empty if members are removed (placeholder objects employed).

   - Groups are emptied before deletion.

   - Rules are created sequentially and appended to the existing policy. Order mirrors that of the CSV file.

   - Any errors are captured and logged.

   - The tool does not ‘commit’ the policy unless the ‘--commit’ switch is provided. This is so the engineer has the option to manually ‘revert to running configuration’. Note: if ‘--commit’ switch is provided and API update errors are encountered then the tool will automatically ‘revert to running configuration’ and release locks.

   - The tool takes configuration and commit locks unless the ‘--no-locks’ or ‘--test’ switch is provided. Note: locks are relinquished unless an update error occurred.

   - The tool checks object existence unless the ‘--no-checks’ switch is provided. 

Caveats:

   - Creating new groups inside new groups in the CSV file is not supported as the order of creation is undetermined. You could achieve this via multiple CSV files and self-managing the import order.

   - Knowledge of the various object trees is helpful as all objects must exist before assignment (e.g. if you intend to use a shared object in a Device Group group it must of course exist first!):

   - When files are output the action column reads ‘__ACTION__’. You will need to edit this if you intend to use the file for import.

   - For rules, you would need to know the VSYS number for the Virtual System.

   - DIPs are per VSYS not shared among the chassis. You need to specify the VSYS in the location field.

   - If the ‘--location’ option is provided, the tool will only act upon matching lines from the CSV file. e.g. Given ‘--l vsys1’, if the CSV file contains location fields containing ‘vsys1’ and ‘vsys2’ then only the lines with ‘vsys1’ will be acted upon.

Use Cases:

The CSV file written by Pandevice will open directly in Microsoft Excel. This makes editing much simpler. Here are a few use cases.

Use Case #1 Migrate objects/policy between Panoramas/Firewalls:

    1. Use the collection method to pull a copy of the objects from a specific Device Group:

	-d <panorama.fqdn> -u admin -p *** -o –l <device_group_name>

    2. Open the file in Microsoft Excel and make any edits you require:

        ◦ Edit ‘op_action’ field to ‘create’.
        ◦ Edit ‘location’ field to name of Device Group to update.
        ◦ Remove any unwanted lines (or hash them out).
        ◦ Save the file.
        ◦ Exit (don’t save again).

    3. Open the file in Notepad to check the Unicode quotes exist.

    4. If you copy the file to a Unix device run ‘dos2unix’ on the file.

    5. Check configuration status on target device (look for unsaved configuration etc).

    6. Upload the file to the new device using Panmanager in ‘--test’ and ‘-v’ mode.

    7. Check for errors in the log.

    8. Re-run the tool without ‘--test’.

    9. Revert to running configuration if errors are seen else ‘commit’.

Use Case #2 Edit Logging Action of rules:

    1. Use the collection method to pull a copy of the objects from a specific Device Group.

	-d <panorama.fqdn> -u admin -p *** -o –l <device_group_name>

    2. 'grep' out the target rules from the file and redirect to a new file.

    3. ‘vi’ this file and do a global search and replace for the ‘log_setting’ field. E.g. 

	:%s/<old log profile name>/<new log profile name>/g

    4. Open file in Microsoft Excel and delete all cells other than the mandatory ones and ‘log_setting’ (or just do this all in Microsoft Excel).

    5. Update to device.
