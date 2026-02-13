Configuration of Interfaces
===========================

.. sectnum::
   :start: 9

.. contents::
   :local:
   :depth: 2


General principles
------------------

FirewallFabrik supports incremental management of the configuration of interfaces. It can add and remove IP addresses, create and destroy VLAN interfaces, and add and remove bridge ports and bonding interface members. Incremental management means generated scripts can add or remove interfaces or addresses only when needed, without having to completely remove configuration and then re-add it back.

For example, in case of IP addresses of interfaces, the script checks if the address configured in the FirewallFabrik GUI really exists on the interface it should belong to. If it is not there, the script adds it, but if it exists, the script does nothing. Running the script again therefore does not disturb the configuration at all. It is not going to remove addresses and then add them back. The same happens with VLAN interfaces, bridge ports, and bonding interfaces.

.. tip::

   If someone reconfigures interfaces, VLANs, or IP addresses on the machine, just run the FirewallFabrik-generated script again and it will restore configuration to the state defined in the GUI without removing everything down first and reconfiguring from scratch. The script runs only those commands that are necessary to undo the changes made by hand.

FirewallFabrik supports Linux only. The following table shows the supported features:

.. list-table:: Supported Interface Configuration Features
   :header-rows: 1
   :widths: 40 12

   * - Feature
     - Linux
   * - IP address management
     - *yes*
   * - Incremental IP address management
     - *yes*
   * - VLAN interfaces
     - *yes*
   * - Incremental management of VLAN interfaces
     - *yes*
   * - Bridge ports
     - *yes*
   * - Incremental management of bridge ports
     - *yes*
   * - Bonding interfaces
     - *yes*
   * - Incremental management of bonding interfaces
     - partial
   * - MTU Configuration
     - no
   * - Cluster configuration: interface configuration for clustering protocols on *Linux*
     - *yes*

The most complete implementation is available on Linux where generated script can incrementally manage IP addresses, VLAN interfaces, bridge ports, and partially bonding interfaces.


IP Address Management
---------------------

* The generated script includes shell code to manage IP addresses of interfaces if checkbox "Configure interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

* The script uses the *ip* tool on Linux which should be present on the firewall. The script checks if it is available and aborts if it cannot find it.

* The script checks if IP address configured in the GUI exists on the firewall and adds it if necessary.

* If the script finds an address on the firewall that is not configured in the FirewallFabrik GUI, it deletes it.


IP Address Management on Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The generated script includes shell code to manage IP addresses if the checkbox "Configure interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

The script uses *ip* tool which should be present on the firewall. The script checks if it is available and aborts if it can not find it. The path to this tool can be changed in the "Host OS" settings dialog of the firewall object. The script then checks if the IP address of each interface configured in the GUI exists on the firewall and adds it if necessary. If the script finds ip address on the firewall that is not configured in the FirewallFabrik GUI, it removes it.

If the checkbox "Clear ip addresses and bring down interfaces not configured in FirewallFabrik" is turned on in the "Script" tab of firewall settings dialog, the script deletes all ip address of all interfaces that are not configured in FirewallFabrik GUI and brings interfaces that are missing in FirewallFabrik but are found on the firewall down. The goal is to ensure that firewall rules operate in the environment that matches assumptions under which they were generated. If the program generated rules assuming some address does not belong to the firewall, but in reality it does, packets may show up in the wrong chain that will lead to the wrong behavior of the firewall. This feature is off by default.

The generated script recognizes command line parameters "start", "stop", "reload", "interfaces" and "test_interfaces". When the script runs with the parameter "interfaces" it performs only interface configuration as described above. The command-line parameter "start" makes it do that and then load iptables rules. Parameter "test_interfaces" makes the script perform all the checks of IP addresses and print commands that it would use to add and remove addresses but not actually execute them.

The generated script can manage both IPv4 and IPv6 addresses.

To illustrate how IP address management works, consider the following example. Interface *eth0* has two IPv4 and two IPv6 addresses:

.. figure:: img/iface-example-ipv4-ipv6-config.png
   :alt: Example configuration with several IPv4 and IPv6 addresses

   Example configuration with several IPv4 and IPv6 addresses

Initial configuration of the addresses on the machine looks like this:

.. code-block:: text

   root@linux-test-1:~# ip addr
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
       inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:aa brd ff:ff:ff:ff:ff:ff
       inet 10.3.14.108/24 brd 10.3.14.255 scope global eth0
       inet6 fe80::20c:29ff:fe1e:dcaa/64 scope link
       valid_lft forever preferred_lft forever
   3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet 10.1.1.1/24 brd 10.1.1.255 scope global eth1
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
       valid_lft forever preferred_lft forever

IPv4 address 10.3.14.108 and IPv6 address fe80::20c:29ff:fe1e:dcaa/64 configured in FirewallFabrik are already present on the machine, but the other IPv4 and IPv6 addresses are not. First, lets see what happens when the script generated by FirewallFabrik runs with command line parameter "test_interfaces":

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-1-s.fw test_interfaces
   # Adding ip address: eth0 192.0.2.1/24
   ip addr add 192.0.2.1/24 dev eth0
   ifconfig eth0 up
   # Adding ip address: eth0 2001:db8:1f0e:162::2/32
   ip addr add 2001:db8:1f0e:162::2/32 dev eth0
   ifconfig eth0 up

The script detected existing addresses and did nothing about them but printed commands it would execute to add missing addresses. We can now run the script with parameter "interfaces" to actually reconfigure the machine, then run it again to demonstrate that after addresses were added, the script is not going to make any unnecessary changes:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-1-s.fw interfaces
   # Adding ip address: eth0 192.0.2.1/24
   # Adding ip address: eth0 2001:db8:1f0e:162::2/32
   root@linux-test-1:~#
   root@linux-test-1:~# /etc/fw/linux-test-1-s.fw test_interfaces
   root@linux-test-1:~#

IP address management works both ways: if the administrator deletes an address in the FirewallFabrik GUI, the script will remove it on the machine. To illustrate this, I am going to remove the second IPv4 and IPv6 addresses from the same interface *eth0* object and then recompile the script and run it again on the machine:

.. figure:: img/iface-config-after-address-removal.png
   :alt: Configuration after additional IPv4 and IPv6 addresses have been removed

   Configuration after additional IPv4 and IPv6 addresses have been removed

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-1-s.fw test_interfaces
   # Removing ip address: eth0 192.0.2.1/24
   ip addr del 192.0.2.1/24 dev eth0
   ifconfig eth0 up
   # Removing ip address: eth0 2001:db8:1f0e:162::2/32
   ip addr del 2001:db8:1f0e:162::2/32 dev eth0
   ifconfig eth0 up

As you can see, the script would delete these addresses on the machine to bring its actual configuration in sync with configuration defined in FirewallFabrik.

.. note::

   The script does not delete "scope link" and "scope host" addresses from interfaces.

   When you change the IP address of an interface in a FirewallFabrik object and then run the generated script on the firewall, the script first adds new address and then removes the old address from the interface.

This flexible incremental management of IP addresses helps simplify basic configuration of the firewall OS. One can use standard OS script and configuration files to configure the machine with just one IP address of one interface, used for management, and let the script generated by FirewallFabrik manage all other IP addresses of all interfaces. With this, FirewallFabrik becomes a configuration GUI for the whole network setup of the firewall machine.


.. _interface-names:

Interface Names
---------------

By default, FirewallFabrik attempts to determine an interface's function based on the name of the interface. For example, on Linux if an interface is named *eth2.102* based on the interface name FirewallFabrik will determine that the interface appears to be a VLAN interface with parent interface *eth2* and VLAN ID 102.

If a user tries to create an interface with a name that doesn't match the expected patterns FirewallFabrik will generate an error. For example, attempting to create the same *eth2.102* interface from our previous example as an interface object directly under a firewall object FirewallFabrik will generate the error shown below.

.. figure:: img/iface-error-incorrect-vlan-name.png
   :alt: Error message when incorrect VLAN interface is created

   Error message displayed when a VLAN interface name does not match the parent interface name.

If instead the *eth2.102* interface were to be created as a child object under the *eth2* interface then FirewallFabrik would not generate the error since the VLAN interface eth2.102 should be a sub-interface of eth2. Note that in this case FirewallFabrik will automatically set the interface type to VLAN and will set the VLAN ID to 102.

You can view and edit the interface type and VLAN ID by clicking the "Advanced Interface Settings ..." button in the editor panel of the interface. An example of the advanced settings for eth2.102, when created as a child interface of eth2, is shown below.

.. figure:: img/iface-advanced-settings-vlan.png
   :alt: Advanced settings for eth2.102 interface showing VLAN type and VLAN ID 102

   Advanced settings for eth2.102 interface showing Device Type set to VLAN and VLAN ID set to 102.

Sometimes you may want to override the default behavior where FirewallFabrik expects interface names to follow a specific naming convention. To disable this feature, open the FirewallFabrik preferences window, click the Objects tab and click the Interface sub-tab in the lower window. Uncheck the checkbox labeled "Verify interface names and autoconfigure their parameters using known name patterns".

.. figure:: img/iface-disable-name-checking.png
   :alt: Preferences dialog showing how to disable automatic name checking

   Disabling automatic interface name checking in the FirewallFabrik preferences dialog. Select the "Objects" tab, then the "Interface" sub-tab, and uncheck the verification checkbox.

In this mode, FirewallFabrik will not auto-populate any fields, even if the interface name matches an expected pattern like *eth2.102*. All interface parameters, such as interface type and VLAN ID, must be configured manually.


.. _advanced-interface-settings:

Advanced Interface Settings
---------------------------

.. _vlan-interfaces:

VLAN Interfaces
---------------

- The generated script includes shell code to manage VLAN interfaces if the checkbox "Configure VLAN interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

- The script uses the *vconfig* tool which should be present on the firewall. The script checks if it is available and aborts if it cannot find it.

- The script checks if the VLAN interface configured in the GUI exists on the firewall and creates it if necessary.

- If the script finds a VLAN interface on the firewall that is not configured in the FirewallFabrik GUI, it deletes it.


.. _vlan-interface-management-on-linux:

VLAN Interface Management on Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A script generated by FirewallFabrik and intended for a Linux firewall can create and remove VLAN interfaces if the checkbox "Configure VLAN interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

As with IP addresses, the script manages VLAN interfaces incrementally; that is, it compares actual configuration of the firewall machine to the configuration defined in FirewallFabrik and then adds or removes VLAN interfaces. Running the same script multiple times does not make any unnecessary changes on the firewall. If actual configuration matches objects created in the FirewallFabrik GUI, the script does not perform any actions and just exits.

The script uses the utility *vconfig* to configure VLAN interfaces. It checks if the utility is present on the firewall machine and aborts execution if it is not found. If this utility is installed in an unusual place on your machine, you can configure the path to it in the "Host OS" settings dialog of the firewall object.

VLAN interfaces can have different names on Linux, depending on the naming convention established using *"vconfig set_name_type"* command. Four naming types are available: VLAN_PLUS_VID (vlan0005), VLAN_PLUS_VID_NO_PAD (vlan5), DEV_PLUS_VID (eth0.0005), DEV_PLUS_VID_NO_PAD (eth0.5). FirewallFabrik supports all four, you just assign the name to the VLAN interface in the GUI and generated script will automatically issue "vconfig set_name_type" command to choose correct name type.

To illustrate VLAN management on Linux, consider the firewall object "linux-test-vlan-1" shown below.

.. figure:: img/iface-vlan-config-linux.png
   :alt: Example configuration with VLAN interfaces added to eth1

   Example configuration of the firewall object "linux-test-vlan-1" showing VLAN interfaces added to eth1.

The interface *eth1* is configured as "unnumbered" interface, we are going to add VLAN subinterfaces to it. To do this, select this interface in the tree and right-click to open the right-click menu:

.. figure:: img/iface-adding-vlan-subinterface.png
   :alt: Adding a VLAN subinterface via right-click context menu

   Right-click context menu on the eth1 interface showing the "New Interface" option to add a VLAN subinterface.

The new subinterface is created with the generic name "Interface". To make it a VLAN interface we should rename it:

.. figure:: img/iface-vlan-subinterface-eth1-100.png
   :alt: VLAN subinterface eth1.100

   The new VLAN subinterface renamed to eth1.100, shown in the object tree and editor panel.

The name of the interface is eth1.100, which implies VLAN ID 100. FirewallFabrik is aware of the naming schemes of VLAN interfaces on Linux and automatically recognizes this name and sets interface type to "VLAN" and its VLAN ID to "100". To inspect and change its VLAN ID, click the "Advanced Interface Settings" button:

.. figure:: img/iface-vlan-parameters-dialog.png
   :alt: VLAN interface parameters dialog

   The VLAN interface parameters dialog showing Device Type set to VLAN and VLAN ID set to 100.

.. note::

   The program verifies the VLAN ID configured in the VLAN interface parameters dialog and compares it to the interface name to make sure they match. It does not let you set a VLAN ID that does not match interface name because vconfig would not let you do it on the Linux machine. The program also verifies subinterface name to make sure it matches one of the supported naming schemes. It allows names such as "eth1.100", "eth1.0100", "vlan100", "vlan0100" but would not allow any other name for the VLAN subinterface.

I am going to add a second VLAN interface eth1.101 and add IPv4 addresses to both VLAN interfaces. The final configuration is shown below.

.. figure:: img/iface-two-vlans-with-addresses.png
   :alt: Two VLAN interfaces with IP addresses

   Final configuration showing two VLAN subinterfaces eth1.100 and eth1.101 under eth1, each with an IPv4 address assigned.

The generated script includes the following shell function that sets up all VLANs and IP addresses:

.. code-block:: bash

   configure_interfaces() {
       :
       # Configure interfaces
       update_vlans_of_interface "eth1 eth1.100 eth1.101"
       clear_vlans_except_known eth1.100@eth1 eth1.101@eth1
       update_addresses_of_interface "lo ::1/128 127.0.0.1/8" ""
       update_addresses_of_interface "eth0 fe80::20c:29ff:fe1e:dcaa/64 10.3.14.108/24" ""
       update_addresses_of_interface "eth1" ""
       update_addresses_of_interface "eth1.100 10.1.1.1/24" ""
       update_addresses_of_interface "eth1.101 10.1.2.1/24" ""
   }

The call to *update_vlans_of_interface* adds and removes VLANs as needed to make sure VLAN interfaces eth1.100 and eth1.101 exist. The call to *clear_vlans_except_known* removes other VLAN interfaces that might exist on the machine but were not configured in FirewallFabrik. Calls to *update_addresses_of_interface* set up IP addresses. To test, I am going to copy the generated script to the firewall and run it with the command-line parameter "test_interfaces". This command does not make any changes on the firewall but only prints commands it would have executed to configure VLANs and addresses:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-vlan-1.fw test_interfaces
   # Adding VLAN interface eth1.100 (parent: eth1)
   vconfig set_name_type DEV_PLUS_VID_NO_PAD
   vconfig add eth1 100
   ifconfig eth1.100 up
   # Adding VLAN interface eth1.101 (parent: eth1)
   vconfig set_name_type DEV_PLUS_VID_NO_PAD
   vconfig add eth1 101
   ifconfig eth1.101 up
   # Interface eth1.100 does not exist
   # Adding ip address: eth1.100 10.1.1.1/24
   ip addr add 10.1.1.1/24 dev eth1.100
   ifconfig eth1.100 up
   # Interface eth1.101 does not exist
   # Adding ip address: eth1.101 10.1.2.1/24
   ip addr add 10.1.2.1/24 dev eth1.101
   ifconfig eth1.101 up

The script uses vconfig to set up the naming scheme and add VLAN interfaces, then uses IP to add addresses. To make the change, run the script with the command-line parameter "interfaces":

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-vlan-1.fw interfaces
   # Adding VLAN interface eth1.100 (parent: eth1)
   Set name-type for VLAN subsystem. Should be visible in /proc/net/vlan/config
   Added VLAN with VID == 100 to IF -:eth1:-
   # Adding VLAN interface eth1.101 (parent: eth1)
   Set name-type for VLAN subsystem. Should be visible in /proc/net/vlan/config
   Added VLAN with VID == 101 to IF -:eth1:-
   # Adding ip address: eth1.100 10.1.1.1/24
   # Adding ip address: eth1.101 10.1.2.1/24

To inspect the result, use the ``ip addr show`` command:

.. code-block:: text

   root@linux-test-1:~# ip addr show
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
       inet6 ::1/128 scope host
          valid_lft forever preferred_lft forever
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:aa brd ff:ff:ff:ff:ff:ff
       inet 10.3.14.108/24 brd 10.3.14.255 scope global eth0
       inet6 fe80::20c:29ff:fe1e:dcaa/64 scope link
          valid_lft forever preferred_lft forever
   3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
          valid_lft forever preferred_lft forever
   4: eth1.100@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet 10.1.1.1/24 scope global eth1.100
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
          valid_lft forever preferred_lft forever
   5: eth1.101@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet 10.1.2.1/24 scope global eth1.101
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
          valid_lft forever preferred_lft forever

Let's try to run the same script again:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-vlan-1.fw interfaces
   root@linux-test-1:~#

The script detected that both VLAN interfaces already exist and have correct IP addresses and did nothing.

Now I am going to change the VLAN ID on one of the interfaces and demonstrate how the script executes the change on the firewall. First, I rename interface eth1.100 to eth1.102:

.. figure:: img/iface-vlan-renamed-eth1-102.png
   :alt: Configuration after renaming VLAN interface eth1.100 to eth1.102

   Configuration after renaming VLAN interface eth1.100 to eth1.102, with the IP address reassigned.

Then I recompile the firewall, copy the generated script to the firewall and run it:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-vlan-1.fw interfaces
   # Adding VLAN interface eth1.102 (parent: eth1)
   Set name-type for VLAN subsystem. Should be visible in /proc/net/vlan/config
   Added VLAN with VID == 102 to IF -:eth1:-
   # Removing VLAN interface eth1.100 (parent: eth1)
   Removed VLAN -:eth1.100:-
   # Adding ip address: eth1.102 10.1.1.1/24

The script added the new VLAN interface eth1.102 first, then removed eth1.100 and added the IP address to eth1.102.

Now lets rename both VLAN interfaces to use different naming scheme:

.. figure:: img/iface-vlans-renamed-naming-scheme.png
   :alt: Configuration after renaming VLAN interfaces eth1.101 and eth1.102 to vlan0101 and vlan0102

   Configuration after renaming VLAN interfaces to use VLAN_PLUS_VID_NO_PAD naming scheme (vlan0101 and vlan0102).

.. note::

   There is a limitation in the implementation of the incremental VLAN management at this time. The generated script cannot correctly rename VLAN interfaces, (that is, change the name) without changing the VLAN ID. There are two workarounds: (1) you can remove VLAN interfaces manually and then run the script to let it add new ones, or (2) you can run the script twice. On the first run, it will issue errors because it can't add the VLAN interfaces with different name but the same VLAN ID, but it can delete old VLAN interfaces. On the second run it adds the VLAN interfaces with new names.

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-vlan-1.fw interfaces
   # Adding VLAN interface vlan0101 (parent: eth1)
   Set name-type for VLAN subsystem. Should be visible in /proc/net/vlan/config
   Added VLAN with VID == 101 to IF -:eth1:-
   # Adding VLAN interface vlan0102 (parent: eth1)
   Set name-type for VLAN subsystem. Should be visible in /proc/net/vlan/config
   Added VLAN with VID == 102 to IF -:eth1:-
   # Adding ip address: vlan0101 10.1.2.1/24
   # Adding ip address: vlan0102 10.1.1.1/24

Here is how final configuration looks:

.. code-block:: text

   root@linux-test-1:~# ip addr ls
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
       inet6 ::1/128 scope host
          valid_lft forever preferred_lft forever
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:aa brd ff:ff:ff:ff:ff:ff
       inet 10.3.14.108/24 brd 10.3.14.255 scope global eth0
       inet6 fe80::20c:29ff:fe1e:dcaa/64 scope link
          valid_lft forever preferred_lft forever
   3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
          valid_lft forever preferred_lft forever
   4: vlan0101@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet 10.1.2.1/24 scope global vlan0101
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
          valid_lft forever preferred_lft forever
   5: vlan0102@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet 10.1.1.1/24 scope global vlan0102
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
          valid_lft forever preferred_lft forever


.. _bridge-ports:

Bridge Ports
------------

Bridge management for Linux firewalls was introduced in FirewallFabrik V4.0. The generated script can manage bridge interfaces as follows:

* The generated script includes shell code to manage bridge interfaces if checkbox "Configure bridge interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

* On Linux firewalls, the generated firewall script uses *brctl* tool which should be present on the firewall. The script checks if brctl is available and aborts if it cannot find it.

* The script checks if the bridge interface configured in the GUI exists on the firewall and creates it if necessary.

* It then checks if the bridge interface on the firewall is configured with bridge ports that were defined in the GUI. It adds those that are missing and removes those that are not configured in the GUI.

* Adding VLAN interfaces as bridge ports, as well as mixing regular Ethernet and VLAN interfaces is supported. That is, the following configuration can be configured in FirewallFabrik and the generated script will create it:

  .. code-block:: text

     bridge name bridge id          STP enabled   interfaces
     br0         8000.000c29f6bebe  no            eth4.102
                                                  eth5

* In order to use a VLAN interface as bridge port, it needs to be created twice in the GUI. The first time, it is created as a child of the regular Ethernet interface and has type "VLAN". The second interface object with the same name should be created as a child of a bridge interface with a type "ethernet".


.. _enabling-bridge-interface-management:

Enabling Bridge Interface Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To enable FirewallFabrik bridge interface management, click the "Configure bridge interfaces" option in the Firewall Settings of the firewall that will include bridge interfaces.

.. figure:: img/iface-bridge-enable-settings.png
   :alt: Example configuration showing the Script tab with "Configure bridge Interfaces" checkbox enabled

   Example configuration; interfaces eth1 and eth2 will become bridge ports. Select the "Script" tab and enable script management of bridge interfaces.

With this setting enabled FirewallFabrik the generated firewall script will manage bridge interfaces on the firewall incrementally. This includes removing any bridge interfaces that are defined on the firewall system but are not defined in the FirewallFabrik configuration.

.. note::

   You can use FirewallFabrik to configure rules for firewalls that have a bridge interface(s) that are not being created and managed by the FirewallFabrik generated script. In this case, you need to create an interface object in FirewallFabrik that has a name that matches the name of the bridge interface on the firewall system.

   For example, if you have a Linux firewall that is already configured with a bridge interface called *br0*, and you don't want FirewallFabrik to manage creating the interface, create an interface object on your firewall called *br0* with no child objects. Use this interface object in rules to represent the br0 interface.


.. _bridge-interface-management-on-linux:

Bridge Interface Management on Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On Linux firewalls, the script generated by FirewallFabrik can create and remove bridge interfaces such as "br0" and also add and remove regular Ethernet interfaces as bridge ports. For the firewall script to manage bridge interfaces this option must be enabled as shown in `Enabling Bridge Interface Management`_. By default, this option is *disabled*.

As with IP addresses and vlans, the script manages bridge incrementally. It compares actual configuration of the firewall with objects defined in the FirewallFabrik GUI and then adds or removes bridge interfaces and bridge ports. Running the same script multiple times does not make any unnecessary changes on the firewall. If actual configuration matches objects created in the FirewallFabrik GUI, script does not perform any actions and just exits.

The script uses utility *brctl* to configure the bridge. It checks if the utility is present on the firewall machine and aborts execution if it is not found. If this utility is installed in an unusual place on your machine, you can configure the path to it in the "Host OS" settings dialog of the firewall object.

To illustrate bridge management on Linux, consider the firewall object "linux-test-bridge-1" shown below:

.. figure:: img/iface-bridge-config-linux.png
   :alt: Example configuration showing linux-test-bridge-1 with eth0, eth1, eth2, and lo interfaces

   Example configuration; interfaces eth1 and eth2 will become bridge ports.

To build the bridge, I need to create bridge interface *"br0"*. This interface is just regular child object of the firewall object in the tree, to create it, select the firewall and right-click to open the context menu, then choose the item "New Interface". The new interface is created with generic name "Interface", rename it to *"br0"*. At this point we have interfaces br0, eth1, and eth2 but the latter two are not configured as bridge ports yet. Interface br0 is not a bridge yet, either.

.. figure:: img/iface-bridge-interface-br0.png
   :alt: Bridge interface br0 added to the firewall object tree

   Bridge interface br0.

To make br0 a bridge, open it in the editor by double-clicking it in the tree and then click the "Advanced Interface Settings" button. This opens a dialog where you can change the interface type and configure some parameters. Set the type to "bridge" and turn STP on if you need it.

.. figure:: img/iface-bridge-type-settings.png
   :alt: Options dialog showing Device Type set to Bridge with Enable STP checkbox

   Configuring bridge interface type.

To make eth1 and eth2 bridge ports, use Cut and Paste operations on the objects in the tree. Paste both interface objects into the br0 interface so that they move to the position right under it in the tree as shown below. Notice how the program automatically recognized them as bridge ports and showed this in the second column of the tree.

.. figure:: img/iface-bridge-ports-configured.png
   :alt: Firewall tree showing eth1 and eth2 as bridge ports under br0

   Configuring bridge ports.

.. note::

   I have started with a firewall object that already had interface objects for eth1 and eth2, but this is not necessary. You can add bridge ports by creating new interface objects under the bridge interface using the right-click context menu and selecting "New Interface".

Notice that bridge ports cannot have IP addresses of their own and corresponding items in the context menu are disabled:

.. figure:: img/iface-bridge-port-disabled-functions.png
   :alt: Context menu for bridge port showing New Address and New Address IPv6 options grayed out

   Functions disabled for bridge port subinterfaces.

To complete interface configuration, we need to add an IP address to interface br0 if it needs one. I am going to add address 10.1.1.1/24 to test with. Then I can compile and run the script on the firewall.

The firewall machine where I am going to run generated script has interfaces eth0, eth1, and eth2 but does not have interface br0 yet. Interfaces eth1 and eth2 are not configured as bridge ports. Lets see how the script generated by FirewallFabrik reconfigures this machine:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-bridge-1.fw  interfaces
   Activating firewall script generated Fri Feb 26 16:53:05 2010 by vadim
   Running prolog script
   # Creating bridge interface
   # Updating bridge configuration: addif br0 eth1
   # Updating bridge configuration: addif br0 eth2
   # Adding ip address: br0 10.1.1.1/24
   Verifying interfaces: lo eth0 br0 eth1 eth2

Using ip and brctl tools to verify configuration:

.. code-block:: text

   root@linux-test-1:~# ip addr show
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
       inet6 ::1/128 scope host
           valid_lft forever preferred_lft forever
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:aa brd ff:ff:ff:ff:ff:ff
       inet 10.3.14.108/24 brd 10.3.14.255 scope global eth0
       inet6 fe80::20c:29ff:fe1e:dcaa/64 scope link
           valid_lft forever preferred_lft forever
   3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
           valid_lft forever preferred_lft forever
   4: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:be brd ff:ff:ff:ff:ff:ff
       inet6 fe80::20c:29ff:fe1e:dcbe/64 scope link
           valid_lft forever preferred_lft forever
   5: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UNKNOWN
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet 10.1.1.1/24 scope global br0
       inet6 fe80::18cb:52ff:fe4b:c6b1/64 scope link
           valid_lft forever preferred_lft forever

.. code-block:: text

   root@linux-test-1:~# brctl show
   bridge name     bridge id               STP enabled     interfaces
   br0             8000.000c291edcb4       no              eth1
                                                           eth2

Now I am going to add another bridge port eth3 to br0, recompile the script, and run it on the firewall. First, add eth3 bridge port in the GUI:

.. figure:: img/iface-bridge-add-third-port.png
   :alt: Firewall tree showing br0 with eth1, eth2, and eth3 as bridge ports

   Adding a third bridge port.

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-bridge-1.fw interfaces
   # Updating bridge configuration: addif br0 eth3

All the script did is add eth3 to br0 bridge. New bridge configuration looks like this:

.. code-block:: text

   root@linux-test-1:~# brctl show
   bridge name     bridge id               STP enabled     interfaces
   br0             8000.000c291edcb4       no              eth1
                                                           eth2
                                                           eth3

.. tip::

   The change that added eth3 to the bridge caused a bridge loop and consequently nasty ARP storm inside my VMWare ESXi server where the virtual machine I used to test bridge configuration was running. I had three virtual switches but I forgot that eth2 and eth3 were attached to the same virtual switch. Needless to say, this ARP storm promptly killed ESXi. Now I am using the traffic shaping feature in ESXi to throttle traffic on the back-end virtual switches that I am using only for testing. Beware of bridge loops when you work with bridging firewalls.

Now let's remove the bridge port in the GUI and see what happens. I am going to delete object eth3 in the GUI, recompile, and run the script on the firewall again:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-bridge-1.fw interfaces
   # Updating bridge configuration: delif br0 eth3

.. code-block:: text

   root@linux-test-1:~# brctl show
   bridge name     bridge id               STP enabled     interfaces
   br0             8000.000c291edcb4       no              eth1
                                                           eth2

As expected, the script returned the bridge configuration to the state it was in before I added eth3.


Bridge with VLAN Interfaces as Bridge Ports
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

FirewallFabrik can generate configuration for the bridging firewall using VLAN interfaces as bridge ports; however, there is a twist to this. Recall from `VLAN Interfaces`_ that VLANs are created in FirewallFabrik as subinterfaces under their respective parent interface. That is, the VLAN interface *"eth1.100"* is an interface object that sits in the tree right under interface *"eth1"*:

.. figure:: img/iface-bridge-vlan-subinterface.png
   :alt: VLAN subinterface eth1.100 shown as a child of eth1

   VLAN subinterface eth1.100.

As we have seen in `Bridge Interface Management on Linux`_ and `Enabling Bridge Interface Management`_, bridge ports are also represented by interface objects located in the tree under corresponding bridge interface, as shown below:

.. figure:: img/iface-bridge-ports-child-objects.png
   :alt: Bridge ports eth1 and eth2 shown as child objects of the bridge interface br0

   Bridge ports are child objects of the bridge interface.

If we want *eth1.100* to work as a bridge port, it must be created twice, once as a child of interface *eth1* and second time as a child of interface *br0*. The first copy represents it as a VLAN subinterface while the second one represents a bridge port.

.. figure:: img/iface-bridge-vlan-as-bridge-ports.png
   :alt: VLAN interfaces eth1.100 and eth1.101 acting as bridge ports under br0 and also listed under eth1

   eth1.100 and eth1.101: VLAN interfaces acting as bridge ports.


.. _bonding-interfaces:

Bonding Interfaces
------------------

Support for bonding interfaces is currently available only for Linux firewalls. A generated iptables script can incrementally update bonding interfaces:

* The generated script includes shell code to manage bonding interfaces if the checkbox "Configure bonding interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

* The script uses *ifenslave* tool which should be present on the firewall. The script checks if it is available and aborts if it cannot find it.

* The script creates new bonding interfaces with parameters configured in the GUI if the module 'bonding' is not loaded. This is what happens if the FirewallFabrik script runs after reboot.

If there are no bonding interfaces in FirewallFabrik configuration, the script removes the bonding module to kill any bonding interfaces that might exist on the machine.

If you add a second bonding interface in FirewallFabrik, the script checks if it exists on the machine. It will not create it because to do so, it would have to remove the module, which kills other bonding interfaces. If this second bonding interface exists, it will be configured with slaves and addresses. If it does not exist, the script aborts. In this case you need to either (1) reload the module manually or (2) add max_bonds=2 to /etc/modules.conf and reboot or (3) unload the module and run the FirewallFabrik script again (if module is not loaded, the script loads it with correct max_bonds parameter)

If a bonding interface exists on the machine but not in FirewallFabrik configuration, the script removes all slaves from it and brings it down. It cannot delete it because to do so it would need to remove the module, which kills other bonding interfaces.

.. note::

   There is a limitation in the current implementation in that all bonding interfaces will use the same protocol parameters. This is because module loading with parameter "-obond1" that is supposed to be the way to obtain more than one bonding interface and also the way to specify different parameters for different interfaces causes kernel panic in my tests. (Tested with bonding module v3.5.0 and kernel 2.6.29.4-167.fc11.i686.PAE on Fedora Core 11.) The only working way to get two bonding interfaces I could find is to load the module with parameter max_bonds=2, but this means all bonding interfaces work with the same protocol parameters. If bond interfaces are configured with different parameters in FirewallFabrik, the compiler uses the first and issues a warning for others.

To configure bonding interface, we start with an interface object with name *"bond0"*. Create this interface as usual, open it in the editor by double clicking it in the tree, rename it, and then and click "Advanced Interface Settings" button. Set the type to "Bonding" in the drop-down list and set the other parameters:

.. figure:: img/iface-bonding-settings.png
   :alt: Options dialog showing Device Type set to Bonding with bonding policy 802.3ad and xmit hash policy layer2

   Bonding interface settings.

To add regular Ethernet interfaces as slaves to a bonding interface, copy and paste (or create) them so they become child objects of a bonding interface. A bonding interface needs an IP address as any other regular interface. Final configuration looks like shown below:

.. figure:: img/iface-bonding-two-slaves.png
   :alt: Bonding interface bond0 with eth2 and eth3 as slaves and IP address 10.1.1.1/255.255.255.0

   Bonding interface bond0 with two slaves.

If you only want to be able to use the bonding interface in rules, then this is sufficient configuration. You can go ahead and add rules and place object "bond0" in "Source", "Destination" or "Interface" column of policy rules. If you want FirewallFabrik to generate a script that creates and configures this interface, then you need to enable support for this by turning the checkbox "Configure bonding interfaces" on in the "Script" tab of the firewall object settings dialog:

.. figure:: img/iface-bonding-enable-settings.png
   :alt: Firewall settings dialog showing Script tab with "Configure bonding Interfaces" checkbox enabled

   Configuration of bonding interfaces should be enabled in firewall settings dialog.

Now compile the firewall object, copy the generated script to the firewall machine and run it there. If the script is started using the command-line parameter "interfaces", it only configures interfaces and IP addresses but does not load iptables rules. Here is how it looks:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-bond-1.fw interfaces
   # Add bonding interface slave: bond0 eth2
   # Add bonding interface slave: bond0 eth3
   # Adding ip address: bond0 10.1.1.1/24

Interface configuration after the script run looks like this:

.. code-block:: text

   root@linux-test-1:~# ip addr show
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
       inet6 ::1/128 scope host
           valid_lft forever preferred_lft forever
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:aa brd ff:ff:ff:ff:ff:ff
       inet 10.3.14.108/24 brd 10.3.14.255 scope global eth0
       inet6 fe80::20c:29ff:fe1e:dcaa/64 scope link
           valid_lft forever preferred_lft forever
   3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:b4 brd ff:ff:ff:ff:ff:ff
       inet6 fe80::20c:29ff:fe1e:dcb4/64 scope link
           valid_lft forever preferred_lft forever
   4: eth2: <BROADCAST,MULTICAST,SLAVE,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master bond0 state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:be brd ff:ff:ff:ff:ff:ff
   5: eth3: <BROADCAST,MULTICAST,SLAVE,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast master bond0 state UP qlen 1000
       link/ether 00:0c:29:1e:dc:be brd ff:ff:ff:ff:ff:ff
   6: bond0: <BROADCAST,MULTICAST,MASTER,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
       link/ether 00:0c:29:1e:dc:be brd ff:ff:ff:ff:ff:ff
       inet 10.1.1.1/24 scope global bond0
       inet6 fe80::20c:29ff:fe1e:dcbe/64 scope link
           valid_lft forever preferred_lft forever

.. code-block:: text

   root@linux-test-1:~# cat /proc/net/bonding/bond0
   Ethernet Channel Bonding Driver: v3.3.0 (June 10, 2008)

   Bonding Mode: IEEE 802.3ad Dynamic link aggregation
   Transmit Hash Policy: layer2 (0)
   MII Status: up
   MII Polling Interval (ms): 100
   Up Delay (ms): 0
   Down Delay (ms): 0

   802.3ad info
   LACP rate: slow
   Active Aggregator Info:
    Aggregator ID: 1
    Number of ports: 1
    Actor Key: 9
    Partner Key: 1
    Partner Mac Address: 00:00:00:00:00:00

   Slave Interface: eth2
   MII Status: up
   Link Failure Count: 0
   Permanent HW addr: 00:0c:29:1e:dc:be
   Aggregator ID: 1

   Slave Interface: eth3
   MII Status: up
   Link Failure Count: 0
   Permanent HW addr: 00:0c:29:1e:dc:c8
   Aggregator ID: 2

Running the script a second time does nothing because interface bond0 already exists and its configuration matches the one defined in FirewallFabrik:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-bond-1.fw interfaces
   root@linux-test-1:~#

.. note::

   Unfortunately, the generated script cannot manage bonding interface parameters. If you change a bonding policy in the GUI, recompile it, and run the script on the firewall, nothing will happen. You need to either manually unload the module or reboot the machine. However, if you add or remove Ethernet interfaces under the bonding interface, the script will update its configuration accordingly without the need to unload the module or reboot the machine.
