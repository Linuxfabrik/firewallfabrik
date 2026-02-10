Cluster Configuration
=====================

.. sectnum::
   :start: 1

.. contents::
   :local:
   :depth: 2


Firewall Builder 4.0 introduced support for firewall clusters. Firewall Builder helps you create configuration for iptables, PF, or PIX rules and in some cases cluster configuration as well. The following state synchronization and failover protocols are supported at this time:

.. list-table:: Supported State Synchronization and Failover Software
   :header-rows: 1
   :widths: 20 25 55

   * - OS
     - State Synchronization
     - Failover
   * - Linux
     - conntrackd
     - vrrpd, heartbeat, keepalived, OpenAIS
   * - OpenBSD/FreeBSD
     - pfsync
     - CARP
   * - Cisco ASA (PIX)
     - PIX state sync protocol
     - PIX failover protocol
   * - Cisco IOS Router
     - None
     - None

Firewall Builder automatically generates policy rules to permit packets of these protocols when it sees firewall cluster configured with one of them. You can use cluster object and its interfaces instead of the member firewall objects or their interfaces in policy and NAT rules and the program will substitute correct addresses when it generates iptables script or PF or PIX configuration.

.. note::

   Cisco IOS router firewall objects can be used in a cluster, but Firewall Builder does not support a failover protocol for IOS router clusters, so no rules are automatically created for this type of cluster.

Detailed description of the Cluster object is provided in :doc:`05 - Working with Objects`.

Linux cluster configuration with Firewall Builder
--------------------------------------------------

Detailed walk-through examples for different Linux, BSD and PIX cluster configurations can be found in Firewall Builder Cookbook chapter Section 14.4.

High Availability (HA) configurations on Linux can be built using different software packages, such as vrrpd (VRRPD) or heartbeat (Linux-HA). Firewall Builder focuses on the firewall configuration and provides independent way of configuring iptables rules for Linux HA clusters and can be used with any HA software package, including home-grown scripts and packages that will appear in the future. At this time Firewall Builder does not generate configuration or command line for the HA software.

Like with all other supported firewall platforms, interface objects that belong to a cluster object serve to establish association between actual interfaces of the member firewalls. Cluster interface object should have the same name as corresponding member firewall interfaces. It should have Failover Group child object configured with interfaces of the member firewalls. You can create Failover Group object using context menu item "Add Failover Group", the menu appears when you right mouse click on the cluster interface object. If you create new cluster using "New object" menu or toolbar button, the wizard that creates new cluster object will create Failover Group objects automatically. Here is how it should look like:

.. figure:: img/cluster-failover-group-mapping.png
   :alt: Failover group objects and mapping between cluster and member interfaces

   Failover group objects and mapping between cluster and member interfaces

Note that the name of the cluster interface should match the name of the member interfaces exactly, even if it may appear that HA software running on the firewall creates new interface such as eth0:0. Heartbeat daemon creates what looks like interface "eth0:0" when it becomes active and assumes virtual ip address. The "eth0:0" is in fact a label on the secondary ip address on the interface "eth0" which you can see if you use command "ip addr show dev eth0". Here is an example of the output of this command taken on the firewall running heartbeat that was active at the moment:

.. code-block:: text

   # ip addr show dev eth0
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN qlen 1000
       link/ether 00:0c:29:1e:dc:aa brd ff:ff:ff:ff:ff:ff
       inet 10.3.14.108/24 brd 10.3.14.255 scope global eth0
       inet 10.3.14.150/24 brd 10.3.14.255 scope global secondary eth0:0
       inet6 fe80::20c:29ff:fele:dcaa/64 scope link
          valid_lft forever preferred_lft forever

Secondary IP address 10.3.14.150 that was added by heartbeat is highlighted in red. The "eth0:0" at the very end of the output is the label assigned to this address, this label makes it appear as another interface in the output of ifconfig, however it is not real interface. Here is the output of ifconfig on the same machine at the same time when it was active in the HA pair:

.. code-block:: text

   # ifconfig
   eth0      Link encap:Ethernet  HWaddr 00:0c:29:1e:dc:aa
             inet addr:10.3.14.108  Bcast:10.3.14.255  Mask:255.255.255.0
             inet6 addr: fe80::20c:29ff:fele:dcaa/64 Scope:Link
             UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
             RX packets:242381 errors:0 dropped:0 overruns:0 frame:0
             TX packets:41664 errors:0 dropped:0 overruns:0 carrier:0
             collisions:0 txqueuelen:1000
             RX bytes:40022382 (40.0 MB)  TX bytes:5926417 (5.9 MB)
             Interrupt:18 Base address:0x2000

   eth0:0    Link encap:Ethernet  HWaddr 00:0c:29:1e:dc:aa
             inet addr:10.3.14.150  Bcast:10.3.14.255  Mask:255.255.255.0
             UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
             Interrupt:18 Base address:0x2000

It is important to understand the distinction because iptables does not recognize eth0:0 as an interface and does not allow it in "-i" or "-o" clause. Firewall Builder follows the same rules as the target firewall platform it prepares configuration for. This means you should build configuration in fwbuilder using interface "eth0" and not "eth0:0".

Each cluster interface should have a Failover Group child object configured with corresponding interfaces of the member firewalls. Configuration of this object implements interface mapping illustrated by the figure above and is shown below:

.. figure:: img/cluster-failover-group-config.png
   :alt: Failover Group object configuration

   Failover Group object configuration

Firewall Builder GUI provides a way to configure some parameters for the failover protocols *heartbeat* and *OpenAIS*. Click *Edit protocol parameters* button to open dialog for this:

.. figure:: img/cluster-heartbeat-parameters.png
   :alt: Editing parameters for the heartbeat protocol

   Editing parameters for the heartbeat protocol

.. figure:: img/cluster-openais-parameters.png
   :alt: Editing parameters for the OpenAIS protocol

   Editing parameters for the OpenAIS protocol

Firewall Builder only supports multicast or unicast heartbeat configuration. You can enter the address and port number in the dialog. If you turn checkbox "Use unicast address" on, generated iptables commands will match source and destination addresses of the corresponding interface of both member firewalls. If this checkbox is off, it is assumed heartbeat is configured to use multicast and generated iptables commands will only match this multicast address in both INPUT and OUTPUT chains.

As with heartbeat, you can configure ip address and port number for the OpenAIS protocol. There is no unicast option here.

Cluster object should also have State Synchronization group child object. Create it using context menu "Add State Synchronization Group" item if this object does not exist. In this object you need to configure member interfaces that should be used for state synchronization. On Linux, state synchronization is done using conntrackd daemon (conntrack-tools). Configure State Synchronization group object with interfaces of the member firewalls used to pass conntrackd packets:

.. figure:: img/cluster-state-sync-group-tree.png
   :alt: State synchronization group object in the tree

   State synchronization group object in the tree

The State Synchronization group object should look like this:

.. figure:: img/cluster-state-sync-group-parameters.png
   :alt: State synchronization group object parameters

   State synchronization group object parameters

Member firewalls and their interfaces appear in the panel in the right hand side of the dialog. Firewall Builder uses this information to automatically generate iptables rules to permit conntrackd packets. Firewall Builder assumes conntrackd is configured to send synchronization packets over dedicated interface (which generally is a good idea anyway). You may use internal interface of the firewall for this purpose as well. See examples of conntrackd configuration in Firewall Builder CookBook. You can configure ip address and port number for the conntrack as well.

.. figure:: img/cluster-conntrack-parameters.png
   :alt: Editing parameters for the Conntrack state synchronization protocol

   Editing parameters for the Conntrack state synchronization protocol

OpenBSD cluster configuration with Firewall Builder
----------------------------------------------------

Documentation for BSD clusters coming soon...

PIX cluster configuration with Firewall Builder
------------------------------------------------

Firewall Builder supports PIX "lan based" failover configuration. Unlike in Linux or BSD, where each interface of the firewall runs its own instance of failover protocol, PIX runs one instance of failover protocol over dedicated interface. PIX can also run state synchronization protocol over the same or another dedicated interface. These dedicated interfaces should be connected via separate switch and do not see regular traffic. Here is how this is implemented in Firewall Builder:

Like with all other supported firewall platforms, interface objects that belong to a cluster object serve to establish association between actual interfaces of the member firewalls. Cluster interface object should have the same name as corresponding member firewall interfaces. It should have Failover Group child object which should be configured with interfaces of the member firewalls. You can create Failover Group object using context menu item "Add Failover Group", the menu appears when you right mouse click on the cluster interface object. Here is an example of correct interface mapping between cluster and member firewalls:

.. figure:: img/cluster-pix-failover-group-mapping.png
   :alt: Failover group objects and mapping between cluster and member interfaces

   Failover group objects and mapping between cluster and member interfaces

The Failover Group object "cluster1:e0.101:members" is configured with interfaces "Ethernet0.101" of both members:

.. figure:: img/cluster-pix-failover-group-object.png
   :alt: Example of failover group object

   Example of failover group object

Interface that is configured for the failover on the member firewall should be marked as "Dedicated Failover". Use checkbox with this name in the interface object dialog to do this.

Cluster interface that corresponds to the failover interface of the members should be configured with protocol "PIX failover protocol". Click on the "Edit protocol parameters" button to edit timeout, poll time and the key.

Cluster interfaces that represent regular interfaces of the members also must have failover group objects; that is where you add interfaces of the member firewalls. There is no need to configure protocol in these failover groups because PIX does not run it over these interfaces. Regular interfaces should not be marked as "Dedicated Failover".

Cluster object should have State Synchronization group child object. Create it using context menu "Add State Synchronization Group" item if this object does not exist. In this object you need to configure member interfaces that should be used for state synchronization. You can use separate dedicated interfaces or the same interfaces used for failover. If these are separate, corresponding interface objects of the member firewalls must be marked as "Dedicated Failover".

One of the member firewall interfaces used in the State Synchronization group must be marked as "master". This is where you define which PIX unit is going to be the primary and which is going to be the secondary in the HA pair.

Here is an example of the state synchronization and failover using the same interface Ethernet2:

.. figure:: img/cluster-pix-state-sync-failover.png
   :alt: Example of the state synchronization and failover using the same interface Ethernet2

   Example of the state synchronization and failover using the same interface Ethernet2

The State Synchronization Group object "State Sync Group" is configured with interfaces "Ethernet2" of both members:

.. figure:: img/cluster-pix-state-sync-group-object.png
   :alt: Example of state synchronization group object

   Example of state synchronization group object

Dedicated failover interfaces of the member firewalls must have IP addresses and these addresses must be different but belong to the same subnet.

Built-in policy installer treats PIX clusters in a special way:

* For the PIX cluster, built-in installer installs generated configuration only on the master PIX unit. It determines which one is the master by looking in the StateSyncGroup object (state synchronization cluster group).

* Dialog where user enters authentication credentials and other parameters for the installer has a checkbox that makes installer initiate copy of the configuration to the standby PIX if installation was successful.

Handling of the cluster rule set and member firewalls rule sets
---------------------------------------------------------------

Normally, only the cluster object should have non-empty policy, NAT and routing rule sets, while member firewall objects should have empty rule sets. In this case, Firewall Builder policy compilers will use rules they find in the cluster. However, if a member firewall has rule set object of any type (Policy, NAT, Routing) with the name the same as the name of the cluster object and the same type, then compilers will use rules from the member firewall and ignore those found in the cluster. They also issue a warning that looks like shown in the figure below:

.. figure:: img/cluster-rule-set-override-warning.png
   :alt: A warning shown when a rule set that belongs to the member firewall overrides rule set that belongs to the cluster

   A warning shown when a rule set that belongs to the member firewall overrides rule set that belongs to the cluster

Suggested use case for this feature is to create a small non-top rule set in the cluster which can be used as a branch using a rule with action "Branch" to pass control to it. The cluster can define some rules in this rule set, these rules are going to be common for all member firewalls. However if for some reason you want to implement these rules differently for one member, you just create rule set with the same name in it and add some different rules there. Of course two members can have the rule set with this name and both will override the one that belongs to the cluster. The warning is only given if member firewall rule set is not empty. If it exists and has the same name as the one that belongs to the cluster, but has no rules, then the warning does not appear.
