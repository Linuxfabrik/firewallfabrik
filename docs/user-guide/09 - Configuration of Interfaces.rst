Configuration of Interfaces
===========================

.. sectnum::
   :start: 1

.. contents::
   :local:
   :depth: 2


General principles
------------------

Firewall Builder 4.0 introduced support incremental management of the configuration of interfaces. It can add and remove IP addresses, create and destroy VLAN interfaces, and add and remove bridge ports and bonding interface members. Incremental management means generated scripts can add or remove interfaces or addresses only when needed, without having to completely remove configuration and then re-add it back.

For example, in case of IP addresses of interfaces, the script checks if the address configured in the Firewall Builder GUI really exists on the interface it should belong to. If it is not there, the script adds it, but if it exists, the script does nothing. Running the script again therefore does not disturb the configuration at all. It is not going to remove addresses and then add them back. The same happens with VLAN interfaces, bridge ports, and bonding interfaces.

.. tip::

   If someone reconfigures interfaces, VLANs, or IP addresses on the machine, just run the Firewall Builder-generated script again and it will restore configuration to the state defined in the GUI without removing everything down first and reconfiguring from scratch. The script runs only those commands that are necessary to undo the changes made by hand.

Not all of these features are available on every supported OS. The following table shows this:

.. list-table:: Supported Interface Configuration Features
   :header-rows: 1
   :widths: 40 12 12 12 12

   * - Feature
     - Linux
     - OpenBSD / FreeBSD
     - Cisco IOS
     - Cisco ASA (PIX)
   * - IP address management
     - *yes*
     - *yes*
     - *yes*
     - *yes*
   * - Incremental IP address management
     - *yes*
     - *yes*
     - no
     - no
   * - VLAN interfaces
     - *yes*
     - *yes*
     - no
     - no
   * - Incremental management of VLAN interfaces
     - *yes*
     - *yes*
     - no
     - no
   * - Bridge ports
     - *yes*
     - *yes*
     - no
     - no
   * - Incremental management of bridge ports
     - *yes*
     - *yes*
     - no
     - no
   * - Bonding interfaces
     - *yes*
     - no
     - no
     - no
   * - Incremental management of bonding interfaces
     - partial
     - no
     - no
     - no
   * - MTU Configuration
     - no
     - *yes*
     - no
     - no
   * - Cluster configuration: *carp* and *pfsync* on *OpenBSD*, interface configuration for failover on *PIX*, interface configuration for clustering protocols on *Linux*
     - *yes*
     - *yes*
     - no
     - *yes*

The most complete implementation is available on Linux where generated script can incrementally manage IP addresses, VLAN interfaces, bridge ports, and partially bonding interfaces.


IP Address Management
---------------------

* The generated script includes shell code to manage IP addresses of interfaces if checkbox "Configure interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

* The script uses the *ip* tool on Linux which should be present on the firewall. The script checks if it is available and aborts if it cannot find it. The script uses *ifconfig* to manage addresses on BSD machines.

* The script checks if IP address configured in the GUI exists on the firewall and adds it if necessary.

* If the script finds an address on the firewall that is not configured in the fwbuilder GUI, it deletes it.


IP Address Management on Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The generated script includes shell code to manage IP addresses if the checkbox "Configure interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

The script uses *ip* tool which should be present on the firewall. The script checks if it is available and aborts if it can not find it. The path to this tool can be changed in the "Host OS" settings dialog of the firewall object. The script then checks if the IP address of each interface configured in the GUI exists on the firewall and adds it if necessary. If the script finds ip address on the firewall that is not configured in the Firewall Builder GUI, it removes it.

If the checkbox "Clear ip addresses and bring down interfaces not configured in fwbuilder" is turned on in the "Script" tab of firewall settings dialog, the script deletes all ip address of all interfaces that are not configured in Firewall Builder GUI and brings interfaces that are missing in Firewall Builder but are found on the firewall down. The goal is to ensure that firewall rules operate in the environment that matches assumptions under which they were generated. If the program generated rules assuming some address does not belong to the firewall, but in reality it does, packets may show up in the wrong chain that will lead to the wrong behavior of the firewall. This feature is off by default.

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

IPv4 address 10.3.14.108 and IPv6 address fe80::20c:29ff:fe1e:dcaa/64 configured in fwbuilder are already present on the machine, but the other IPv4 and IPv6 addresses are not. First, lets see what happens when the script generated by fwbuilder runs with command line parameter "test_interfaces":

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

IP address management works both ways: if the administrator deletes an address in the Firewall Builder GUI, the script will remove it on the machine. To illustrate this, I am going to remove the second IPv4 and IPv6 addresses from the same interface *eth0* object and then recompile the script and run it again on the machine:

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

As you can see, the script would delete these addresses on the machine to bring its actual configuration in sync with configuration defined in Firewall Builder.

.. note::

   The script does not delete "scope link" and "scope host" addresses from interfaces.

   When you change the IP address of an interface in a Firewall Builder object and then run the generated script on the firewall, the script first adds new address and then removes the old address from the interface.

This flexible incremental management of IP addresses helps simplify basic configuration of the firewall OS. One can use standard OS script and configuration files to configure the machine with just one IP address of one interface, used for management, and let the script generated by fwbuilder manage all other IP addresses of all interfaces. With this, Firewall Builder becomes a configuration GUI for the whole network setup of the firewall machine.


IP Address Management on BSD
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Firewall Builder usually generates a firewall script file to configure system parameters such as network interfaces, IP addresses, static routes. Starting with Firewall Builder V4.2, FreeBSD firewalls can be configured to generate system settings in rc.conf format. Section 12.6.1.1 explains how to configure Firewall Builder for FreeBSD firewalls using rc.conf format.

All configuration information shown below assumes the standard behavior where Firewall Builder generates a firewall script to manage system settings.

The generated script includes shell code to manage ip addresses if checkbox "Configure interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

The script uses the *ifconfig* utility to add and remove IP addresses. The path to ifconfig can be changed in the "Host OS" settings dialog of the firewall object. The script checks if the IP address of each interface configured in the GUI exists on the firewall and adds it if necessary. If the script finds the IP address on the firewall that is not configured in the Firewall Builder GUI, it removes it. The goal is to ensure that firewall rules operate in the environment that matches assumptions under which they were generated.

The generated script can manage both IPv4 and IPv6 addresses.

To illustrate how IP address management works, consider the following example. All interfaces have both IPv4 and IPv6 addresses:

.. figure:: img/iface-bsd-example-ipv4-ipv6-config.png
   :alt: Example BSD configuration with several IPv4 and IPv6 addresses

   Example BSD configuration with several IPv4 and IPv6 addresses

Initial configuration of the addresses on the machine looks like this:

.. code-block:: text

   # ifconfig -a
   lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 33208
           groups: lo
           inet 127.0.0.1 netmask 0xff000000
           inet6 ::1 prefixlen 128
           inet6 fe80::1%lo0 prefixlen 64 scopeid 0x4
   pcn0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
           lladdr 00:0c:29:83:4d:25
           groups: egress
           media: Ethernet autoselect
           inet 10.3.14.50 netmask 0xffffff00 broadcast 10.3.14.255
           inet6 fe80::20c:29ff:fe83:4d25%pcn0 prefixlen 64 scopeid 0x1
   em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
           lladdr 00:0c:29:83:4d:2f
           media: Ethernet autoselect (1000baseT full-duplex,master)
           status: active
           inet 10.1.1.50 netmask 0xffffff00 broadcast 10.1.1.255
           inet6 fe80::20c:29ff:fe83:4d2f%em0 prefixlen 64 scopeid 0x2
   enc0: flags=0<> mtu 1536
   pflog0: flags=141<UP,RUNNING,PROMISC> mtu 33208
           groups: pflog

Interface pcn0 already has IPv4 and IPv6 addresses that match those configured in Firewall Builder, but interface em0 only has one IPv4 address and only link-local IPv6 address and does not have other addresses configured in Firewall Builder. Lets see what happens when the script generated by Firewall Builder runs on the machine:

.. code-block:: text

   # /etc/fw/openbsd-test-1-s.fw
   Activating firewall script generated Tue Feb 23 16:39:30 2010 by vadim
   net.inet.ip.forwarding: 0 -> 1
   # Adding ip address: em0 192.0.2.12 netmask 0xffffff00
   # Adding ip address: em0 2001:db8:1f0e:162::20 prefixlen 32
   #

The script detected existing addresses and did nothing about them. It also added missing addresses. Here is what we get:

.. code-block:: text

   # ifconfig -A
   lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 33208
           groups: lo
           inet 127.0.0.1 netmask 0xff000000
           inet6 ::1 prefixlen 128
           inet6 fe80::1%lo0 prefixlen 64 scopeid 0x4
   pcn0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
           lladdr 00:0c:29:83:4d:25
           groups: egress
           media: Ethernet autoselect
           inet 10.3.14.50 netmask 0xffffff00 broadcast 10.3.14.255
           inet6 fe80::20c:29ff:fe83:4d25%pcn0 prefixlen 64 scopeid 0x1
   em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
           lladdr 00:0c:29:83:4d:2f
           media: Ethernet autoselect (1000baseT full-duplex,master)
           status: active
           inet 10.1.1.50 netmask 0xffffff00 broadcast 10.1.1.255
           inet6 fe80::20c:29ff:fe83:4d2f%em0 prefixlen 64 scopeid 0x2
           inet 192.0.2.12 netmask 0xffffff00 broadcast 192.0.2.255
           inet6 2001:db8:1f0e:162::20 prefixlen 32
   enc0: flags=0<> mtu 1536
   pflog0: flags=141<UP,RUNNING,PROMISC> mtu 33208
           groups: pflog

I am going to run the script again to demonstrate that after addresses were added, it is not going to make any unnecessary changes:

.. code-block:: text

   # /etc/fw/openbsd-test-1-s.fw
   Activating firewall script generated Tue Feb 23 16:39:30 2010 by vadim
   net.inet.ip.forwarding: 1 -> 1
   #

IP address management works both ways: if the administrator deletes an address in the Firewall Builder GUI, the script will remove it on the machine. To illustrate this, I am going to remove the second IPv4 and IPv6 addresses from the same interface *em0* object and then recompile the script and run it again on the machine:

.. figure:: img/iface-bsd-config-after-address-removal.png
   :alt: BSD configuration after additional IPv4 and IPv6 addresses have been removed

   BSD configuration after additional IPv4 and IPv6 addresses have been removed

.. code-block:: text

   # /etc/fw/openbsd-test-1-s.fw
   Activating firewall script generated Tue Feb 23 16:46:26 2010 by vadim
   net.inet.ip.forwarding: 1 -> 1
   # Removing ip address: em0 192.0.2.12 netmask 0xffffff00
   # Removing ip address: em0 2001:db8:1f0e:162::20 prefixlen 32
   #

As you can see, the script deleted these addresses on the machine to bring its actual configuration in sync with configuration defined in Firewall Builder.

.. note::

   The script does not delete "scope link" and "scope host" addresses from interfaces.

   When you change IP address of an interface in Firewall Builder object and then run the generated script on the firewall, the script first adds new address and then removes the old address from the interface.

This flexible incremental management of IP addresses helps simplify basic configuration of the firewall OS. One can use standard OS script and configuration files to configure the machine with just one IP address of one interface, used for management, and let the script generated by Firewall Builder manage all other IP addresses of all interfaces. With this, Firewall Builder becomes a configuration GUI for the whole network setup of the firewall machine.


.. _interface-names:

Interface Names
---------------

By default, Firewall Builder attempts to determine an interface's function based on the name of the interface. For example, on Linux if an interface is named *eth2.102* based on the interface name Firewall Builder will determine that the interface appears to be a VLAN interface with parent interface *eth2* and VLAN ID 102.

If a user tries to create an interface with a name that doesn't match the expected patterns Firewall Builder will generate an error. For example, attempting to create the same *eth2.102* interface from our previous example as an interface object directly under a firewall object Firewall Builder will generate the error shown below.

.. figure:: img/iface-error-incorrect-vlan-name.png
   :alt: Error message when incorrect VLAN interface is created

   Error message displayed when a VLAN interface name does not match the parent interface name.

If instead the *eth2.102* interface were to be created as a child object under the *eth2* interface then Firewall Builder would not generate the error since the VLAN interface eth2.102 should be a sub-interface of eth2. Note that in this case Firewall Builder will automatically set the interface type to VLAN and will set the VLAN ID to 102.

You can view and edit the interface type and VLAN ID by clicking the "Advanced Interface Settings ..." button in the editor panel of the interface. An example of the advanced settings for eth2.102, when created as a child interface of eth2, is shown below.

.. figure:: img/iface-advanced-settings-vlan.png
   :alt: Advanced settings for eth2.102 interface showing VLAN type and VLAN ID 102

   Advanced settings for eth2.102 interface showing Device Type set to VLAN and VLAN ID set to 102.

Sometimes you may want to override the default behavior where Firewall Builder expects interface names to follow a specific naming convention. To disable this feature, open the Firewall Builder preferences window, click the Objects tab and click the Interface sub-tab in the lower window. Uncheck the checkbox labeled "Verify interface names and autoconfigure their parameters using known name patterns".

.. figure:: img/iface-disable-name-checking.png
   :alt: Preferences dialog showing how to disable automatic name checking

   Disabling automatic interface name checking in the Firewall Builder preferences dialog. Select the "Objects" tab, then the "Interface" sub-tab, and uncheck the verification checkbox.

In this mode, Firewall Builder will not auto-populate any fields, even if the interface name matches an expected pattern like *eth2.102*. All interface parameters, such as interface type and VLAN ID, must be configured manually.


.. _advanced-interface-settings:

Advanced Interface Settings
---------------------------

.. _setting-interface-mtu:

Setting Interface MTU
~~~~~~~~~~~~~~~~~~~~~

Starting with Firewall Builder V4.2, it is possible to configure an interface's MTU (Maximum Transmission Unit). Currently this feature is only available on BSD (OpenBSD and FreeBSD) firewalls.

To configure an interface's MTU value, double-click the interface to open it for editing in the Editor Panel. Click the Advanced Interface Settings button. This will open the configuration window shown below.

.. figure:: img/iface-mtu-settings-bsd.png
   :alt: Modifying interface MTU on a BSD firewall

   The Advanced Interface Settings dialog on a BSD firewall, showing the "Set MTU" checkbox enabled with a value of 2500.

Click the checkbox called Set MTU and adjust the MTU to the desired value. Click OK.

For example, configuring this on interface *eth0* will result in the following command being included in the generated firewall script.

.. code-block:: bash

   ifconfig eth0 mtu 2500


.. _vlan-interfaces:

VLAN Interfaces
---------------

- The generated script includes shell code to manage VLAN interfaces if the checkbox "Configure VLAN interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

- The script uses the *vconfig* tool which should be present on the firewall. The script checks if it is available and aborts if it cannot find it.

- The script checks if the VLAN interface configured in the GUI exists on the firewall and creates it if necessary.

- If the script finds a VLAN interface on the firewall that is not configured in the fwbuilder GUI, it deletes it.


.. _vlan-interface-management-on-linux:

VLAN Interface Management on Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A script generated by Firewall Builder and intended for a Linux firewall can create and remove VLAN interfaces if the checkbox "Configure VLAN interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

As with IP addresses, the script manages VLAN interfaces incrementally; that is, it compares actual configuration of the firewall machine to the configuration defined in Firewall Builder and then adds or removes VLAN interfaces. Running the same script multiple times does not make any unnecessary changes on the firewall. If actual configuration matches objects created in the Firewall Builder GUI, the script does not perform any actions and just exits.

The script uses the utility *vconfig* to configure VLAN interfaces. It checks if the utility is present on the firewall machine and aborts execution if it is not found. If this utility is installed in an unusual place on your machine, you can configure the path to it in the "Host OS" settings dialog of the firewall object.

VLAN interfaces can have different names on Linux, depending on the naming convention established using *"vconfig set_name_type"* command. Four naming types are available: VLAN_PLUS_VID (vlan0005), VLAN_PLUS_VID_NO_PAD (vlan5), DEV_PLUS_VID (eth0.0005), DEV_PLUS_VID_NO_PAD (eth0.5). Fwbuilder supports all four, you just assign the name to the VLAN interface in the GUI and generated script will automatically issue "vconfig set_name_type" command to choose correct name type.

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

The name of the interface is eth1.100, which implies VLAN ID 100. Firewall Builder is aware of the naming schemes of VLAN interfaces on Linux and automatically recognizes this name and sets interface type to "VLAN" and its VLAN ID to "100". To inspect and change its VLAN ID, click the "Advanced Interface Settings" button:

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

The call to *update_vlans_of_interface* adds and removes VLANs as needed to make sure VLAN interfaces eth1.100 and eth1.101 exist. The call to *clear_vlans_except_known* removes other VLAN interfaces that might exist on the machine but were not configured in Firewall Builder. Calls to *update_addresses_of_interface* set up IP addresses. To test, I am going to copy the generated script to the firewall and run it with the command-line parameter "test_interfaces". This command does not make any changes on the firewall but only prints commands it would have executed to configure VLANs and addresses:

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


.. _vlan-interface-management-on-bsd:

VLAN Interface Management on BSD
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Unlike on Linux, on OpenBSD, the name of the VLAN interfaces is restricted to the *"vlanNNN"* scheme. We start with a basic firewall object with two interfaces and will add VLAN interfaces to interface *em0*. Note that *em0* is configured as "unnumbered", this is a requirement for the VLAN parent interface object.

.. figure:: img/iface-bsd-vlan-firewall-object.png
   :alt: OpenBSD test firewall object

   The OpenBSD test firewall object "openbsd-test-vlan-1" with interfaces em0 (unnumbered), lo0, and pcn0.

To create VLAN subinterfaces, select the parent interface object in the tree and right-click to open the context menu:

.. figure:: img/iface-bsd-adding-vlan-subinterface.png
   :alt: Adding a VLAN subinterface on BSD via right-click context menu

   Right-click context menu on the em0 interface showing the "New Interface" option.

The new interface is created with generic name "Interface" and needs to be renamed:

.. figure:: img/iface-bsd-vlan-subinterface-vlan100.png
   :alt: VLAN subinterface vlan100 on BSD

   The new VLAN subinterface renamed to vlan100, shown in the object tree and editor panel.

Firewall Builder is aware of the naming convention for VLAN interfaces on BSD and automatically recognized *vlan100* as a VLAN interface with VLAN ID 100. To inspect or change the VLAN ID, click "Advanced Interface Settings" button:

.. figure:: img/iface-bsd-vlan-parameters-dialog.png
   :alt: Editing VLAN interface parameters on BSD

   The VLAN interface parameters dialog for vlan100 on BSD, showing Device Type set to VLAN and VLAN ID set to 100.

.. note::

   Firewall Builder verifies that the name of the subinterface is acceptable as the name of a VLAN interface on OpenBSD system. You can use name that looks like "vlan100" but it won't accept "em0.100" or any other.

I am going to add second VLAN interface eth1.101 and add IPv4 addresses to both VLAN interfaces. The final configuration is shown below.

.. figure:: img/iface-bsd-two-vlans-with-addresses.png
   :alt: Two VLAN interfaces with IP addresses on BSD

   Final configuration showing two VLAN subinterfaces vlan100 and vlan101 under em0, each with an IPv4 address assigned.

Compiling this firewall object produces script /etc/fw/openbsd-test-vlan-1.fw and PF configuration file /etc/fw/openbsd-test-vlan-1.conf. To activate the firewall and configure the interface, run script /etc/fw/openbsd-test-vlan-1.fw:

.. code-block:: text

   # /etc/fw/openbsd-test-vlan-1.fw
   Activating firewall script generated Fri Feb 26 14:57:54 2010 by vadim
   net.inet.ip.forwarding: 0 -> 1
   # Creating vlan interface vlan100
   # Creating vlan interface vlan101
   # Adding VLAN interface vlan100 (parent: em0)
   # Adding VLAN interface vlan101 (parent: em0)
   # Adding ip address: vlan100 10.1.1.1 netmask 0xffffff00
   # Adding ip address: vlan101 10.1.2.1 netmask 0xffffff00

Here is how configuration of the VLAN interfaces looks like in the output of ifconfig:

.. code-block:: text

   vlan100: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
           lladdr 00:0c:29:83:4d:2f
           vlan: 100 priority: 0 parent interface: em0
           groups: vlan
           inet6 fe80::20c:29ff:fe83:4d2f%vlan100 prefixlen 64 scopeid 0x6
           inet 10.1.1.1 netmask 0xffffff00 broadcast 10.1.1.255
   vlan101: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
           lladdr 00:0c:29:83:4d:2f
           vlan: 101 priority: 0 parent interface: em0
           groups: vlan
           inet6 fe80::20c:29ff:fe83:4d2f%vlan101 prefixlen 64 scopeid 0x7
           inet 10.1.2.1 netmask 0xffffff00 broadcast 10.1.2.255

Let's try to run the same script again:

.. code-block:: text

   #  /etc/fw/openbsd-test-vlan-1.fw
   Activating firewall script generated Fri Feb 26 14:57:54 2010 by vadim
   net.inet.ip.forwarding: 0 -> 1

The script detected that both VLAN interfaces already exist and have correct IP addresses and made no changes to their configuration.

Let's change the VLAN ID of the interface vlan100. I cannot change the VLAN ID without changing its name. When I rename interface vlan100 to vlan102 in Firewall Builder, it changes its VLAN ID automatically.

.. figure:: img/iface-bsd-vlan100-renamed-vlan102.png
   :alt: Interface vlan100 renamed to vlan102

   Configuration after renaming vlan100 to vlan102, with vlan101 unchanged.

Here is what happens when I run the generated script on the firewall:

.. code-block:: text

   #  /etc/fw/openbsd-test-vlan-1.fw
   Activating firewall script generated Fri Feb 26 15:57:03 2010 by vadim
   net.inet.ip.forwarding: 1 -> 1
   # Deleting vlan interface vlan100
   # Creating vlan interface vlan102
   # Adding VLAN interface vlan102 (parent: em0)
   # Adding ip address: vlan102 10.1.1.1 netmask 0xffffff00

Ifconfig shows that interface vlan100 was removed and vlan102 added:

.. code-block:: text

   vlan101: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
           lladdr 00:0c:29:83:4d:2f
           vlan: 101 priority: 0 parent interface: em0
           groups: vlan
           inet6 fe80::20c:29ff:fe83:4d2f%vlan101 prefixlen 64 scopeid 0x14
           inet 10.1.2.1 netmask 0xffffff00 broadcast 10.1.2.255
   vlan102: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
           lladdr 00:0c:29:83:4d:2f
           vlan: 102 priority: 0 parent interface: em0
           groups: vlan
           inet6 fe80::20c:29ff:fe83:4d2f%vlan102 prefixlen 64 scopeid 0x17
           inet 10.1.1.1 netmask 0xffffff00 broadcast 10.1.1.255


.. _bridge-ports:

Bridge Ports
------------

Bridge management for Linux firewalls was introduced in Firewall Builder V4.0 and support for bridges in BSD (OpenBSD and FreeBSD) firewalls was added in Firewall Builder V4.2. The generated script can manage bridge interfaces as follows:

* The generated script includes shell code to manage bridge interfaces if checkbox "Configure bridge interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

* On Linux firewalls, the generated firewall script uses *brctl* tool which should be present on the firewall. The script checks if brctl is available and aborts if it cannot find it.

* On OpenBSD firewalls, the generated firewall script uses *brconfig* tool which should be present on the firewall. The script checks if brconfig is available and aborts if it cannot find it.

* On FreeBSD firewalls, the generated firewall script uses *ifconfig* tool which should be present on the firewall. The script checks if ifconfig is available and aborts if it cannot find it.

* The script checks if the bridge interface configured in the GUI exists on the firewall and creates it if necessary.

* It then checks if the bridge interface on the firewall is configured with bridge ports that were defined in the GUI. It adds those that are missing and removes those that are not configured in the GUI.

* Adding VLAN interfaces as bridge ports, as well as mixing regular Ethernet and VLAN interfaces is supported. That is, the following configuration can be configured in Firewall Builder and the generated script will create it:

  .. code-block:: text

     bridge name bridge id          STP enabled   interfaces
     br0         8000.000c29f6bebe  no            eth4.102
                                                  eth5

* In order to use a VLAN interface as bridge port, it needs to be created twice in the GUI. The first time, it is created as a child of the regular Ethernet interface and has type "VLAN". The second interface object with the same name should be created as a child of a bridge interface with a type "ethernet".


.. _enabling-bridge-interface-management:

Enabling Bridge Interface Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To enable Firewall Builder bridge interface management, click the "Configure bridge interfaces" option in the Firewall Settings of the firewall that will include bridge interfaces.

.. figure:: img/iface-bridge-enable-settings.png
   :alt: Example configuration showing the Script tab with "Configure bridge Interfaces" checkbox enabled

   Example configuration; interfaces eth1 and eth2 will become bridge ports. Select the "Script" tab and enable script management of bridge interfaces.

With this setting enabled Firewall Builder the generated firewall script will manage bridge interfaces on the firewall incrementally. This includes removing any bridge interfaces that are defined on the firewall system but are not defined in the Firewall Builder configuration.

.. note::

   You can use Firewall Builder to configure rules for firewalls that have a bridge interface(s) that are not being created and managed by the Firewall Builder generated script. In this case, you need to create an interface object in Firewall Builder that has a name that matches the name of the bridge interface on the firewall system.

   For example, if you have a Linux firewall that is already configured with a bridge interface called *br0*, and you don't want Firewall Builder to manage creating the interface, create an interface object on your firewall called *br0* with no child objects. Use this interface object in rules to represent the br0 interface.


.. _bridge-interface-management-on-linux:

Bridge Interface Management on Linux
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On Linux firewalls, the script generated by Firewall Builder can create and remove bridge interfaces such as "br0" and also add and remove regular Ethernet interfaces as bridge ports. For the firewall script to manage bridge interfaces this option must be enabled as shown in `Enabling Bridge Interface Management`_. By default, this option is *disabled*.

As with IP addresses and vlans, the script manages bridge incrementally. It compares actual configuration of the firewall with objects defined in the Firewall Builder GUI and then adds or removes bridge interfaces and bridge ports. Running the same script multiple times does not make any unnecessary changes on the firewall. If actual configuration matches objects created in the Firewall Builder GUI, script does not perform any actions and just exits.

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

The firewall machine where I am going to run generated script has interfaces eth0, eth1, and eth2 but does not have interface br0 yet. Interfaces eth1 and eth2 are not configured as bridge ports. Lets see how the script generated by Firewall Builder reconfigures this machine:

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

Firewall Builder can generate configuration for the bridging firewall using VLAN interfaces as bridge ports; however, there is a twist to this. Recall from `VLAN Interfaces`_ that VLANs are created in Firewall Builder as subinterfaces under their respective parent interface. That is, the VLAN interface *"eth1.100"* is an interface object that sits in the tree right under interface *"eth1"*:

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


.. _bridge-interface-management-on-bsd:

Bridge Interface Management on BSD
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On BSD firewalls, the script generated by Firewall Builder can create and remove bridge interfaces such as "bridge0" and also add and remove regular Ethernet interfaces as bridge ports. This function is controlled by the checkbox "Configure bridge interfaces" in the "Script" tab of the firewall object Firewall Settings dialog as shown in `Enabling Bridge Interface Management`_. By default, bridge interface management is turned off.

As with IP addresses and vlans, the script manages bridges incrementally. It compares actual configuration of the firewall with objects defined in the Firewall Builder GUI and then adds or removes bridge interfaces and bridge ports. Running the same script multiple times does not make any unnecessary changes on the firewall. If actual configuration matches objects created in the Firewall Builder GUI, the script does not perform any actions and just exits.

For OpenBSD systems, the script uses utility *brconfig* to configure the bridge. It checks if the utility is present on the firewall machine and aborts execution if it is not found. If this utility is installed in an unusual place on your machine, you can configure the path to it in the "Host OS" settings dialog of the firewall object.

For FreeBSD systems, the script uses utility *ifconfig* to configure the bridge. It checks if the utility is present on the firewall machine and aborts execution if it is not found. If this utility is installed in an unusual place on your machine, you can configure the path to it in the "Host OS" settings dialog of the firewall object.

To illustrate bridge management on FreeBSD, consider firewall object "freebsd-test-bridge-1" shown below:

.. figure:: img/iface-bsd-bridge-initial-objects.png
   :alt: Initial firewall objects for freebsd-test-bridge-1 showing Policy, NAT, Routing, em0, and lo0

   Example configuration; initial firewall objects.

To build the bridge, I need to create the bridge interface *"bridge0"*. This interface is just a regular child object of the firewall object in the tree: to create it, select the firewall and right-click to open the context menu, then select "New Interface". The new interface is created with the generic name "Interface"; rename it to *"bridge0"*.

.. figure:: img/iface-bsd-bridge-interface-bridge0.png
   :alt: Bridge interface bridge0 added to the freebsd-test-bridge-1 firewall tree

   Bridge interface bridge0.

To make bridge0 a bridge interface, open it in the editor by double clicking it in the tree and then click "Advanced Interface Settings" button. This opens a dialog where you can change interface type and configure some parameters. Set type to "Bridge" and turn STP on if you need it.

.. figure:: img/iface-bsd-bridge-type-settings.png
   :alt: Options dialog showing Device Type set to Bridge with MTU, Options, and Enable STP settings

   Configuring bridge interface type.

Now we need to add the interfaces that will be bridge ports of this bridge. Right-click the bridge0 interface and select New Interface. This creates a child interface object below the bridge0 interface. Rename this interface to match the physical interface on the server that will be a bridge port. In this example we will use the em1 interface.

Firewall Builder will automatically detect that this interface is a bridge port since the parent interface type is set to bridge.

.. figure:: img/iface-bsd-bridge-port-editor.png
   :alt: Editor for em1 interface showing it is recognized as a Bridge Port Interface

   Editor for the em1 interface shows it is a bridge port.

Add the second bridge port by repeating the process and adding another child interface to bridge0. In this example, the second interface is em2.

.. figure:: img/iface-bsd-bridge-two-ports.png
   :alt: Bridge interface bridge0 with em1 and em2 as bridge ports

   Bridge interface with two bridge ports.

Bridge interfaces can be optionally configured with an IP address. If the bridge interface is not going to have an IP address assigned the bridge interface needs to be updated to be an unnumbered interface. Double-click the bridge0 interface to open it for editing. Click the radio button to set the type to Unnumbered interface.

.. figure:: img/iface-bsd-bridge-unnumbered.png
   :alt: Bridge0 interface editor with Unnumbered interface radio button selected

   Configuring bridge ports with unnumbered interface setting.

Compiling and installing the generated script on a FreeBSD 8.1 firewall named free-bsd-1 results in the following bridge0 interface configuration.

.. code-block:: text

   free-bsd-1# ifconfig bridge0
   bridge0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
       ether 22:ae:66:38:73:c7
       id 00:00:00:00:00:00 priority 32768 hellotime 2 fwddelay 15
       maxage 20 holdcnt 6 proto rstp maxaddr 100 timeout 1200
       root id 00:00:00:00:00:00 priority 32768 ifcost 0 port 0
       member: em3 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>
               ifmaxaddr 0 port 4 priority 128 path cost 20000
       member: em2 flags=143<LEARNING,DISCOVER,AUTOEDGE,AUTOPTP>
               ifmaxaddr 0 port 3 priority 128 path cost 20000
   free-bsd-1#


.. _bonding-interfaces:

Bonding Interfaces
------------------

Support for bonding interfaces is currently available only for Linux firewalls. A generated iptables script can incrementally update bonding interfaces:

* The generated script includes shell code to manage bonding interfaces if the checkbox "Configure bonding interfaces" is turned on in the "Script" tab of the firewall object "advanced" settings dialog. By default, it is turned off.

* The script uses *ifenslave* tool which should be present on the firewall. The script checks if it is available and aborts if it cannot find it.

* The script creates new bonding interfaces with parameters configured in the GUI if the module 'bonding' is not loaded. This is what happens if the Firewall Builder script runs after reboot.

If there are no bonding interfaces in fwbuilder configuration, the script removes the bonding module to kill any bonding interfaces that might exist on the machine.

If you add a second bonding interface in Firewall Builder, the script checks if it exists on the machine. It will not create it because to do so, it would have to remove the module, which kills other bonding interfaces. If this second bonding interface exists, it will be configured with slaves and addresses. If it does not exist, the script aborts. In this case you need to either (1) reload the module manually or (2) add max_bonds=2 to /etc/modules.conf and reboot or (3) unload the module and run the Firewall Builder script again (if module is not loaded, the script loads it with correct max_bonds parameter)

If a bonding interface exists on the machine but not in Firewall Builder configuration, the script removes all slaves from it and brings it down. It cannot delete it because to do so it would need to remove the module, which kills other bonding interfaces.

.. note::

   There is a limitation in the current implementation in that all bonding interfaces will use the same protocol parameters. This is because module loading with parameter "-obond1" that is supposed to be the way to obtain more than one bonding interface and also the way to specify different parameters for different interfaces causes kernel panic in my tests. (Tested with bonding module v3.5.0 and kernel 2.6.29.4-167.fc11.i686.PAE on Fedora Core 11.) The only working way to get two bonding interfaces I could find is to load the module with parameter max_bonds=2, but this means all bonding interfaces work with the same protocol parameters. If bond interfaces are configured with different parameters in fwbuilder, the compiler uses the first and issues a warning for others.

To configure bonding interface, we start with an interface object with name *"bond0"*. Create this interface as usual, open it in the editor by double clicking it in the tree, rename it, and then and click "Advanced Interface Settings" button. Set the type to "Bonding" in the drop-down list and set the other parameters:

.. figure:: img/iface-bonding-settings.png
   :alt: Options dialog showing Device Type set to Bonding with bonding policy 802.3ad and xmit hash policy layer2

   Bonding interface settings.

To add regular Ethernet interfaces as slaves to a bonding interface, copy and paste (or create) them so they become child objects of a bonding interface. A bonding interface needs an IP address as any other regular interface. Final configuration looks like shown below:

.. figure:: img/iface-bonding-two-slaves.png
   :alt: Bonding interface bond0 with eth2 and eth3 as slaves and IP address 10.1.1.1/255.255.255.0

   Bonding interface bond0 with two slaves.

If you only want to be able to use the bonding interface in rules, then this is sufficient configuration. You can go ahead and add rules and place object "bond0" in "Source", "Destination" or "Interface" column of policy rules. If you want Firewall Builder to generate a script that creates and configures this interface, then you need to enable support for this by turning the checkbox "Configure bonding interfaces" on in the "Script" tab of the firewall object settings dialog:

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

Running the script a second time does nothing because interface bond0 already exists and its configuration matches the one defined in Firewall Builder:

.. code-block:: text

   root@linux-test-1:~# /etc/fw/linux-test-bond-1.fw interfaces
   root@linux-test-1:~#

.. note::

   Unfortunately, the generated script cannot manage bonding interface parameters. If you change a bonding policy in the GUI, recompile it, and run the script on the firewall, nothing will happen. You need to either manually unload the module or reboot the machine. However, if you add or remove Ethernet interfaces under the bonding interface, the script will update its configuration accordingly without the need to unload the module or reboot the machine.
