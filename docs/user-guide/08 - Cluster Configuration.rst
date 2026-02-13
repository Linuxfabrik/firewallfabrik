Cluster Configuration
=====================

.. sectnum::
   :start: 8

.. contents::
   :local:
   :depth: 2


FirewallFabrik supports firewall clusters for Linux. FirewallFabrik helps you create configuration for iptables/nftables rules and in some cases cluster configuration as well. The following state synchronization and failover protocols are supported:

.. list-table:: Supported State Synchronization and Failover Software
   :header-rows: 1
   :widths: 20 25 55

   * - OS
     - State Synchronization
     - Failover
   * - Linux
     - conntrackd
     - vrrpd, heartbeat, keepalived, OpenAIS

FirewallFabrik automatically generates policy rules to permit packets of these protocols when it sees firewall cluster configured with one of them. You can use cluster object and its interfaces instead of the member firewall objects or their interfaces in policy and NAT rules and the program will substitute correct addresses when it generates iptables script.

Detailed description of the Cluster object is provided in :doc:`05 - Working with Objects`.

Linux cluster configuration with FirewallFabrik
------------------------------------------------

Detailed walk-through examples for Linux cluster configurations can be found in :doc:`14 - FirewallFabrik Cookbook`.

High Availability (HA) configurations on Linux can be built using different software packages, such as vrrpd (VRRPD) or heartbeat (Linux-HA). FirewallFabrik focuses on the firewall configuration and provides independent way of configuring iptables rules for Linux HA clusters and can be used with any HA software package, including home-grown scripts and packages that will appear in the future. At this time FirewallFabrik does not generate configuration or command line for the HA software.

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

It is important to understand the distinction because iptables does not recognize eth0:0 as an interface and does not allow it in "-i" or "-o" clause. FirewallFabrik follows the same rules as the target firewall platform it prepares configuration for. This means you should build configuration in FirewallFabrik using interface "eth0" and not "eth0:0".

Each cluster interface should have a Failover Group child object configured with corresponding interfaces of the member firewalls. Configuration of this object implements interface mapping illustrated by the figure above and is shown below:

.. figure:: img/cluster-failover-group-config.png
   :alt: Failover Group object configuration

   Failover Group object configuration

FirewallFabrik GUI provides a way to configure some parameters for the failover protocols *heartbeat* and *OpenAIS*. Click *Edit protocol parameters* button to open dialog for this:

.. figure:: img/cluster-heartbeat-parameters.png
   :alt: Editing parameters for the heartbeat protocol

   Editing parameters for the heartbeat protocol

.. figure:: img/cluster-openais-parameters.png
   :alt: Editing parameters for the OpenAIS protocol

   Editing parameters for the OpenAIS protocol

FirewallFabrik only supports multicast or unicast heartbeat configuration. You can enter the address and port number in the dialog. If you turn checkbox "Use unicast address" on, generated iptables commands will match source and destination addresses of the corresponding interface of both member firewalls. If this checkbox is off, it is assumed heartbeat is configured to use multicast and generated iptables commands will only match this multicast address in both INPUT and OUTPUT chains.

As with heartbeat, you can configure ip address and port number for the OpenAIS protocol. There is no unicast option here.

Cluster object should also have State Synchronization group child object. Create it using context menu "Add State Synchronization Group" item if this object does not exist. In this object you need to configure member interfaces that should be used for state synchronization. On Linux, state synchronization is done using conntrackd daemon (conntrack-tools). Configure State Synchronization group object with interfaces of the member firewalls used to pass conntrackd packets:

.. figure:: img/cluster-state-sync-group-tree.png
   :alt: State synchronization group object in the tree

   State synchronization group object in the tree

The State Synchronization group object should look like this:

.. figure:: img/cluster-state-sync-group-parameters.png
   :alt: State synchronization group object parameters

   State synchronization group object parameters

Member firewalls and their interfaces appear in the panel in the right hand side of the dialog. FirewallFabrik uses this information to automatically generate iptables rules to permit conntrackd packets. FirewallFabrik assumes conntrackd is configured to send synchronization packets over dedicated interface (which generally is a good idea anyway). You may use internal interface of the firewall for this purpose as well. See examples of conntrackd configuration in :doc:`14 - FirewallFabrik Cookbook`. You can configure ip address and port number for the conntrack as well.

.. figure:: img/cluster-conntrack-parameters.png
   :alt: Editing parameters for the Conntrack state synchronization protocol

   Editing parameters for the Conntrack state synchronization protocol

Handling of the cluster rule set and member firewalls rule sets
---------------------------------------------------------------

Normally, only the cluster object should have non-empty policy, NAT and routing rule sets, while member firewall objects should have empty rule sets. In this case, FirewallFabrik policy compilers will use rules they find in the cluster. However, if a member firewall has rule set object of any type (Policy, NAT, Routing) with the name the same as the name of the cluster object and the same type, then compilers will use rules from the member firewall and ignore those found in the cluster. They also issue a warning that looks like shown in the figure below:

.. figure:: img/cluster-rule-set-override-warning.png
   :alt: A warning shown when a rule set that belongs to the member firewall overrides rule set that belongs to the cluster

   A warning shown when a rule set that belongs to the member firewall overrides rule set that belongs to the cluster

Suggested use case for this feature is to create a small non-top rule set in the cluster which can be used as a branch using a rule with action "Branch" to pass control to it. The cluster can define some rules in this rule set, these rules are going to be common for all member firewalls. However if for some reason you want to implement these rules differently for one member, you just create rule set with the same name in it and add some different rules there. Of course two members can have the rule set with this name and both will override the one that belongs to the cluster. The warning is only given if member firewall rule set is not empty. If it exists and has the same name as the one that belongs to the cluster, but has no rules, then the warning does not appear.
