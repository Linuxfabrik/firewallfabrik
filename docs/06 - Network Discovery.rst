Network Discovery: A Quick Way to Create Objects
=================================================

.. sectnum::
   :start: 6

.. contents::
   :local:
   :depth: 3

One of the distinguishing features that Firewall Builder provides is support for automated object creation. This helps populate the objects tree for large networks with lots of hosts and subnets. What might take hours to do manually, the Discovery Druid wizard can help you do in minutes.

To start the Discovery Druid, select Tools/Discovery Druid.

The Discovery Druid supports three main methods for automated object creation:

* Reading the /etc/hosts file
* Performing network discovery using SNMP queries
* Importing the configuration of a firewall or router

You choose the method on the first page of the Druid.

.. figure:: img/discovery-druid-method-selection.png
   :alt: Calling the Object Discovery Druid

   Calling the Object Discovery Druid

Just check the radio button next to the method you want to use and click Next.


Reading the /etc/hosts file
---------------------------

This method imports the host records present in the standard */etc/hosts* file or any other file that contain records in the following format (this format is actually described in the manual page hosts(5)).

``IP_Address host_name``

The IP address must be separated from the host name with any number of spaces or tab symbols. Lines starting with '#' are considered comments and are ignored.

When you choose the import from /etc/hosts on the first page, the Druid asks you for the file path and name on the next page. Once that information is entered, it reads the contents of that file and presents a table of new networks.

.. figure:: img/discovery-choose-hosts-file.png
   :alt: Choosing the File for Import

   Choosing the File for Import

Once you have chosen the file, click Next to let the program read and parse it. The file should be in "/etc/hosts" format; that is it should have an address and host name on each line, separated by any number of white spaces. Here is an example::

    192.2.0.1 test1
    192.2.0.2 test2
    10.1.1.2  serv2
    10.1.1.3  serv3

.. figure:: img/discovery-parsing-hosts-file.png
   :alt: Parsing a File in Hosts Format

   Parsing a File in Hosts Format

Once the program finishes importing, you can click Next to move on to the next page where you can choose which of the addresses you want to use:

.. figure:: img/discovery-choose-addresses.png
   :alt: Choosing the Addresses To Be Used

   Choosing the Addresses To Be Used

You can select any number of addresses in the left panel and use buttons "-->" and "<--" to add or remove them to the panel on the right. The "Select All" and "Unselect All" buttons help to work with large lists of addresses.

.. figure:: img/discovery-choose-addresses-populated.png
   :alt: Choosing the Addresses To Be Used

   Choosing the Addresses To Be Used

Choose the object library where new address objects should be created on the next page:

.. figure:: img/discovery-choose-object-library.png
   :alt: Choosing the Object Library

   Choosing the Object Library

Once you click Finish, objects are created and shown in the tree:

.. figure:: img/discovery-new-address-objects-tree.png
   :alt: New Address Objects in the Tree

   New Address Objects in the Tree


Network Discovery
-----------------

Another powerful way to find addresses of subnets and hosts on the network is to use the SNMP crawler.

.. figure:: img/discovery-snmp-seed-host.png
   :alt: Initial Parameters for the Network Discovery Program

   Initial Parameters for the Network Discovery Program

The Network Discovery program (sometimes referred to as the "Network Crawler") needs a host from which to start. This host is called the "seed host"; you enter it in the first page of the Druid. The crawler implements the following algorithm (this is a somewhat simplified explanation):

First, it runs several SNMP queries against the seed host trying to collect the list of its interfaces and its ARP and routing tables. This host is then added to the table of discovered network objects, together with the host's interfaces, their addresses and netmasks, and the host's "sysinfo" parameters. Then the crawler analyses the routing table of that host; this allows it to discover the networks and subnets, which in turn are also added to the list of discovered objects. Then it analyses the ARP table, which holds MAC and IP addresses of neighboring hosts. It takes one host at a time from this table and repeats the same algorithm, using the new host as a seed host. When it pulls an ARP table from the next host, it discards entries that describe objects it already knows about. However, if it finds new entries, it tries them as well and thus travels further down the network. Eventually, it will visit every host on all subnets on the network.

This algorithm relies on hosts answering SNMP queries. If the very first host (the "seed" host) does not run an SNMP agent, the crawler will stop on the first run of its algorithm and won't find anything. Therefore, it is important to use a host which does run an SNMP agent as a "seed" host. Even if most of the hosts on the network do not run SNMP agents, but a few do, the crawler will most likely find all of them. This happens because it discovers objects when it reads the ARP tables from the host which answers; so even if discovered hosts do not answer to SNMP queries, the crawler can discover them.

One of the ways to limit the scope of the network that the crawler visits is to use the "Confine scan to the network" parameter. You need to enter both a network address and a netmask; the crawler will then check if the hosts it discovers belong to this network and if they do not, discard them.

.. figure:: img/discovery-snmp-parameters-page1.png
   :alt: Parameters for Network Discovery: Page 1

   Parameters for Network Discovery: Page 1

.. figure:: img/discovery-snmp-parameters-page2.png
   :alt: Parameters for Network Discovery: Page 2

   Parameters for Network Discovery: Page 2

There are a few settings that affect the crawler's algorithm. Here is the list:

* Run network scan recursively

  As was described above, the crawler starts with the "seed" host and then repeats its algorithm using every discovered host as a new "seed". If this option is turned OFF, then the crawler runs its algorithm only once and stops.

* Follow point-to-point links

  If a firewall or router has a point-to-point interface (for example, PPP interface), then the crawler can automatically calculate the IP address of the other side of this interface. It then continues the discovery process by querying a router on the other side. Very often, the point-to-point link connects the organization's network to an ISP and you are not really interested in collecting data about your ISP network. By default, the crawler does not cross point-to-point links, but this option, if activated, permits it.

* Include virtual addresses

  Sometimes servers or routers have more than one IP address assigned to the same interface. If this option is turned on, the crawler "discovers" these virtual addresses and tries to create objects for them.

* Run reverse name lookup queries to determine host names

  If a host discovered by the crawler answers to SNMP queries, it report its name, which the crawler uses to create an object in Firewall Builder. However, if the host does not answer the query, the crawler cannot determine its name and only knows its IP address. The crawler can use DNS to back-resolve such addresses and determine host names if this option is turned ON.

* SNMP (and DNS) query parameters

  You must specify the SNMP "read" community string to be used for SNMP queries. You can also specify the number of retries and a timeout for the query. (The number of retries and timeout parameters also apply to DNS and reverse DNS queries.)

Once all parameters are entered, the crawler actually gets to work, which may take a while. Depending on the size of the network and such parameters as the SNMP timeout value, scanning may take minutes or even hours. The progress of the scanner can be monitored on the page in the Druid.

.. figure:: img/discovery-snmp-crawler-status.png
   :alt: The SNMP Crawler Status

   The SNMP Crawler Status

.. figure:: img/discovery-snmp-crawler-status-more.png
   :alt: The SNMP Crawler Status (More)

   The SNMP Crawler Status (More)

You can always stop the crawler using the "Stop network scan" button. Data does not get lost if you do this as the Druid will use whatever objects the crawler discovered before you stopped it.

The "Save scan log to file" button saves the content of the progress window to a text file and is mostly used for troubleshooting and bug reports related to the crawler.

If the crawler succeeded and was able to collect information it needed to create objects, you can switch to the next page where you choose and create objects.

.. figure:: img/discovery-creating-networks.png
   :alt: Creating Networks Using Gathered Information

   Creating Networks Using Gathered Information

This part of the Druid is the same for all discovery methods.

The left column shows the networks that were discovered. The right column shows the network objects that will be created. To start with, the right column is empty.

This page of the Druid also has the following buttons:

* Select All

  Selects all records in the column.

* Unselect All

  Deselects all records in the column.

* Filter

  Brings up a filter dialog. Filtering helps manage long lists of objects.

* Remove Filter

  Removes the currently applied filter and shows all records in the table.

The Druid can filter records in the table either by their address, by their name, or by both. To filter by address enter part of it in the "Address" field. The program compares the text entered in the filter dialog with an address in the table and shows only those records whose address starts with the text of the filter. For example, to only filter out hosts with addresses on the net 10.3.14.0 we could use the filter "10.3.14". Likewise, to remove hosts "bear" and "beaver" (addresses 10.3.14.50 and 10.3.14.74) we could use the filter "10.3.14.6". Note that the filter string does not contain any wildcard symbols like "*". The filter shows only records that have addresses which literally match the filter string.

Filtering by the object name uses the POSIX regular expressions syntax described in the manual page regex(7). For example, to find all records whose names start with "f" we could use the regular expression "^f". The "^" symbol matches the beginning of the string, so this regular expression matches any name that starts with "f". To find all names that end with "somedomain.com", we could use the regular expression ".*somedomain.com$"

Once you have reviewed the discovered networks, decide which ones you want to turn into Network objects. Then, copy those networks to the right column.

To populate the right column with objects, select the networks you want, then click the right arrow (-->) to put them in the right column.

.. figure:: img/discovery-creating-networks-populated.png
   :alt: Creating Networks Using Gathered Information (more)

   Creating Networks Using Gathered Information (more)

Click Next. The discovered hosts list displays:

.. figure:: img/discovery-creating-hosts.png
   :alt: Creating Hosts Using Gathered Information

   Creating Hosts Using Gathered Information

Again, populate the right column with the objects you want to create:

.. figure:: img/discovery-creating-hosts-populated.png
   :alt: Creating Hosts Using Gathered Information (More)

   Creating Hosts Using Gathered Information (More)

Click Next. The final object list displays:

.. figure:: img/discovery-list-of-objects.png
   :alt: List of Objects

   List of Objects

Here you can specify which type of object will be created for each discovered item: address, host, or firewall. Here, we are changing the object "sveasoft (10.3.14.202)" from a host to a firewall:

.. figure:: img/discovery-specify-type-of-object.png
   :alt: Specify Type of Object

   Specify Type of Object

Click Next. The target library control appears:

.. figure:: img/discovery-target-library.png
   :alt: Target Library

   Target Library

Here you can specify which library the objects will appear in. Normally this would be User, unless you have created a user-defined library. Click Next.

The wizard finishes processing, and your new objects appear in your library:

.. figure:: img/discovery-target-library-tree.png
   :alt: Target Library

   Target Library


Importing Existing Firewall Configurations into Firewall Builder
----------------------------------------------------------------

Existing firewall configurations can be imported into Firewall Builder using the Import Firewall wizard. Import is supported for the following platforms.

* iptables
* Cisco IOS router access-lists
* Cisco ASA / Cisco PIX (requires Firewall Builder V4.2 or greater)
* PF


Importing Existing Firewall Configurations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To start the Import Firewall wizard select the File -> Import Firewall menu item. This launches the wizard.

.. figure:: img/import-firewall-wizard.png
   :alt: Main Import Firewall Wizard

   Main Import Firewall Wizard

To start the import process, use the Browse function to select the file that contains the firewall configuration that you want to import.

.. note::

   The configuration file format must match one of the supported platforms listed above. See the platform-specific notes below.

iptables
^^^^^^^^

The configuration file format must be in the iptables-save format. For example, run the ``iptables-save > myfirewall.conf`` command on the firewall you want to import, transfer that file to the system running the Firewall Builder application and select this file in the import wizard.

Cisco IOS router access-lists
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Cisco IOS router access-lists must be in the format displayed when the "show run" command is executed. Copy the output from the "show run" command to a file on the system that Firewall Builder is running on.

Cisco ASA / Cisco PIX
^^^^^^^^^^^^^^^^^^^^^

Cisco ASA and Cisco PIX configurations must be in the format displayed when the "show run" command is executed. Copy the output from the "show run" command to a file an the system that Firewall Builder is running on.

PF
^^

PF configurations must be in a single pf.conf configuration file, Firewall Builder does not support anchors with external files. All configurations must make use of the "quick" keyword. For more information see `Information Regarding PF Import`_.

After you have selected the configuration file to import click on the Continue button.

Firewall Builder will automatically detect the type of configuration file that is being imported and will display a preview of the file in the window.

.. figure:: img/import-configuration-preview.png
   :alt: Import Firewall Wizard - Configuration Preview

   Import Firewall Wizard - Configuration Preview

Click the Continue button. On the next page, enter a name for the firewall object that will be created.

.. figure:: img/import-set-firewall-name.png
   :alt: Import Firewall Wizard - Set Firewall Name

   Import Firewall Wizard - Set Firewall Name

.. note::

   By default, the option to "Find and use existing objects" is enabled. When this option is enabled Firewall Builder will attempt to match elements in in the firewall's configuration file with objects that are already configured in the Firewall Builder object tree. This includes both Standard Library objects and objects the user has created.

   For example, if an imported firewall configuration file has an object or rule that uses TCP port 22, SSH, Firewall Builder will match that to the pre-existing Standard ssh object instead of creating a new TCP service object.

After entering the firewall object name, click Commit. Firewall Builder will show a log of the import process and will include any warning messages in blue colored text and any error messages in red colored text.

.. figure:: img/import-process-log.png
   :alt: Import Firewall Wizard - Import Process Log

   Import Firewall Wizard - Import Process Log

Depending on the platform, this will either be the final step of the wizard or the user will be guided through platform specific configuration activities.

Cisco ASA/PIX/FWSM
^^^^^^^^^^^^^^^^^^^

.. note::

   Firewall Builder will not properly import objects whose names start with a number instead of a letter. For example, an object group with the name "10-net" will not be imported, but the object group with the name "net-10" will be imported.


iptables Import Example
~~~~~~~~~~~~~~~~~~~~~~~

For this example we are going to import a very basic iptables configuration from a firewall that matches the diagram in the figure below.

.. figure:: img/import-firewall-example-diagram.png
   :alt: Firewall Example

   Firewall Example

Firewall Builder imports iptables configs in the format of iptables-save. Script **iptables-save** is part of the standard iptables install and should be present on all Linux distribution. Usually this script is installed in */sbin/*.

When you run this script, it dumps the current iptables configuration to stdout. It reads iptables rules directly form the kernel rather than from some file, so what it dumps is what is really working right now. To import this into Firewall Builder, run the script to save the configuration to a file::

    iptables-save > linux-1.conf

As you can see in the output below, the linux-1.conf iptables configuration is very simple with only a few filter rules and one nat rule.

.. code-block:: text

    # Completed on Mon Apr 11 21:23:33 2011
    # Generated by iptables-save v1.4.4 on Mon Apr 11 21:23:33 2011
    *filter
    :INPUT DROP [145:17050]
    :FORWARD DROP [0:0]
    :OUTPUT DROP [1724:72408]
    :LOGDROP - [0:0]
    -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    -A INPUT -i eth1 -s 10.10.10.0/24 -d 10.10.10.1/32 -p tcp -m tcp --dport 22 -m state --state NEW -j ACCEPT
    -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    -A FORWARD -o eth0 -s 10.10.10.0/24 -p tcp -m tcp --dport 80 -m state --state NEW -j ACCEPT
    -A FORWARD -o eth0 -s 10.10.10.0/24 -p tcp -m tcp --dport 443 -m state --state NEW -j ACCEPT
    -A FORWARD -j LOGDROP
    -A LOGDROP -j LOG
    -A LOGDROP -j DROP
    COMMIT
    # Completed on Mon Apr 11 21:23:33 2011
    # Generated by iptables-save v1.4.4 on Mon Apr 11 21:23:33 2011
    *nat
    :PREROUTING ACCEPT [165114:22904965]
    :OUTPUT ACCEPT [20:1160]
    :POSTROUTING ACCEPT [20:1160]
    -A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
    COMMIT
    # Completed on Mon Apr 11 21:23:33 2011

If you are running Firewall Builder on a different system than the one that is running iptables copy ``linux-1.conf`` from the firewall to the system where Firewall Builder is running.

Launch the Import wizard by selecting the File -> Import Firewall menu item.

Click Browse to find ``linux-1.conf``.

.. figure:: img/import-select-file.png
   :alt: Select File containing iptables-save data

   Select File containing iptables-save data

Click Continue to move to the next window which shows a preview of the configuration file that will be imported and the type of firewall that Firewall Builder has detected it to be.

.. figure:: img/import-detected-platform-preview.png
   :alt: Preview showing detected platform and configuration data

   Preview showing detected platform and configuration data

Next you need to enter a name for the firewall. This is the name that will be used in Firewall Builder to refer to the firewall after it is imported. When you click the Commit button the configuration data will be read.

By default, Firewall Builder attempts to detect if there are items, like IP addresses, used in the rules that match existing items in the object tree. If there is a match the existing item is used, if there is no match a new object is created. This feature can be disabled by unchecking the box next to "Find an use existing objects" which will result in objects being created for evry item used in the imported rules regardless of whether it already exists in the object tree or no.

.. figure:: img/import-entering-firewall-name.png
   :alt: Entering the Name of the Firewall

   Entering the Name of the Firewall

After the import is complete, Firewall Builder displays a log showing all the actions that were taken during the import. Warning messages are displayed in blue font and Error messages are displayed in red.

.. figure:: img/import-log-status-warnings.png
   :alt: Import Log with Status and Warning/Error Messages

   Import Log with Status and Warning/Error Messages

The program tries to interpret the configuration file rule by rule and recreates the equivalent rule in Firewall Builder. The progress window displays warning and error messages, if any, as well as some diagnostics that shows network and service objects created in the process.

.. note::

   Firewall Builder detected that there are rules in the iptables configuration that allow RELATED and ESTABLISHED traffic through the firewall. This behavior can be controlled by a setting in Firewall Builder, so a warning message is shown.

Click the Done button to complete the firewall import.

After the import is completed, the newly created firewall object will be displayed in the object tree. If you expand the Objects system folder, you can also see the Address and Network objects that were created during the import process.

.. figure:: img/import-firewall-objects-tree.png
   :alt: Imported Firewall and Created Objects in Object Tree

   Imported Firewall and Created Objects in Object Tree


Common iptables Post-Import Actions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After the firewall object is created in the object tree there are typically a few more steps required in order to be able to manage your firewall configuration using Firewall Builder.

Interfaces
''''''''''

There is not enough information in the iptables configuration for Firewall Builder to deterministically determine what interfaces and IP addresses are configured on the firewall. During the import if a rule contains either "-i" or "-o" interface references Firewall Builder will add the interface to the firewall object, but some interfaces may not be used in rules and therefore will not be detected.

In the example configuration that was imported for linux-1, both the eth0 and eth1 interfaces were used in the configuration, so the firewall object includes these interfaces. By default Firewall Builder marks these interfaces as Unnumbered.

To update the eth0 interface, double-click it to open it for editing. The figure below shows how to set a label for the interface and to identify that it should have a static IP address.

.. figure:: img/import-editing-eth0-parameters.png
   :alt: Editing Parameters for eth0

   Editing Parameters for eth0

Right-click the interface and select New Address to add an IP address to the interface. Set the IP address and netmask to match your environment.

.. figure:: img/import-setting-ip-address-eth0.png
   :alt: Setting IP Address for eth0

   Setting IP Address for eth0

.. note::

   You may also need to add additional interfaces to the firewall object depending on what Firewall Builder was able to detect from the iptables rules. To add a new interface right-click the firewall object (in our example linux-1) and select New Interface. Add the interface name and label and set the type. The default type is Static IP address.

Rules
'''''

During the import of the linux-1.conf file, Firewall Builder displayed a warning message that there were rules defined to allow RELATED and ESTABLISHED traffic to the firewall. Instead of having to explicitly have a rule for this, Firewall Builder has a configuration option controlling this behavior.

To view the configuration option controlling RELATED and ESTABLISHED traffic double-click on the firewall object and click on the Firewall Settings button in the Editor Panel. The dialog window will open with the Compiler tab selected. About halfway down the window is the checkbox that controls RELATED and ESTABLISHED traffic, which is enabled by default.

.. figure:: img/import-firewall-settings-related-established.png
   :alt: Firewall Settings Option for Controlling RELATED and ESTABLISHED Traffic

   Firewall Settings Option for Controlling RELATED and ESTABLISHED Traffic

Since the default is to allow RELATED and ESTABLISHED traffic, the imported rules 0 and 2 are not necessary. To remove these rules right-click the rule number and select Remove Rule.

.. figure:: img/import-removing-unnecessary-rules.png
   :alt: Removing Unnecessary Rules for RELATED and ESTABLISHED

   Removing Unnecessary Rules for RELATED and ESTABLISHED

.. note::

   The specific rule numbers will vary based on your configuration, but the rules created for matching RELATED and ESTABLISHED traffic are identifiable by the use of the predefined ESTABLISHED object in the Service field of the rule.

NAT rules
''''''''''

To view the imported NAT rules, double-click the NAT object under the linux-1 object in the tree. In this example, there is a single source NAT rule that translates inside addresses to the eth0 (outside) interface of the firewall.

.. figure:: img/import-nat-rules.png
   :alt: NAT Rules

   NAT Rules

User-Defined Chains
''''''''''''''''''''

If your iptables configuration includes user-defined chains, Firewall Builder will create a new Policy object for each user chain and will use the Branch feature to jump from the main Policy to the user chain Policy. In our example linux-1.conf configuration there is a user chain called LOGDROP that has 2 rules. The first rule logs the packet and the second rule drops it.

To view the rules in the LOGDROP policy, double-click the LOGDROP policy object located under the linux-1 firewall object. This will open the rules in the Rules Editor.

.. figure:: img/import-logdrop-policy-rules.png
   :alt: Rules in LOGDROP policy

   Rules in LOGDROP policy


Information Regarding PF Import
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Most firewall platforms like iptables, Cisco ASA, etc. are designed based on a first match and exit paradigm and these firewalls also usually have an implicit "deny all" rule as the last rule in the firewall. This means that anything that is not explicitly allowed is denied. Firewall Builder is also designed with this approach and we even add an explicit "deny all" rule as our final entry in the firewall rules to enforce this behavior.

PF is a bit unique in that it does not require first match and exit behavior. You can force match and exit behavior by using the "quick" keyword, but by default traffic in a PF firewall will traverse all rules and each time a rule is matched the action or other parameters are updated. Once the entire rule set has been evaluated the packet is checked to see what parameter values have been set and and the firewall will act based on those parameters.

When Firewall Builder generates a PF policy, we always use the "quick" command and we add a "block all" command at the end of the configuration file. This makes PF behave the same way as other firewalls that we configure which helps to maintain consistency across platforms. The problem that arises is when we need to import a pf.conf configuration that has "block all" at the top of the configuration and that does not make use of the "quick" command. Since we don't generate rules this way we don't have a way to import configurations that use this format.


Example of PF configuration that IS NOT supported
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following is an example of a pf.conf style that *cannot* be imported into Firewall Builder.

.. code-block:: text

    block in log
    pass out keep state
    pass in on em0 proto tcp from any to self port 22 keep state
    pass in on em0 proto udp from any to self port 53 keep state


Example of PF configuration that IS supported
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following is an example of a pf.conf style that *is* supported for importing into Firewall Builder.

.. code-block:: text

    pass out keep state
    pass in quick on em0 proto tcp from any to self port 22 keep state
    pass in quick on em0 proto udp from any to self port 53 keep state
    block in log
