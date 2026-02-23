Definitions and Terms
======================

.. sectnum::
   :start: 3

.. contents::
   :local:
   :depth: 2

This chapter defines common terms used throughout FirewallFabrik.


Objects
-------

Everything in FirewallFabrik is represented as an **object**. Addresses, networks, hosts, firewalls, services, groups, time intervals, and rules are all objects. Objects can be reused across multiple firewalls and rule sets.


Library
-------

A **library** is a top-level container that organizes objects. FirewallFabrik uses several libraries:

Standard Library
   Ships with the application and contains predefined objects such as common services (HTTP, SSH, DNS, etc.) and standard address objects (e.g. "any"). This library is read-only.

User Library
   The working library where you create and manage your own firewalls, addresses, services, and rules.

Template Library
   Contains template firewall objects that can be used as a starting point when creating new firewall configurations.


Devices
-------

Host
   A **host** represents a networked device (server, workstation, router, etc.) that has network interfaces but is not a firewall. Hosts appear in rules as sources or destinations.

Firewall
   A **firewall** is a specialized host that represents an actual firewall device. It owns Policy, NAT, and Routing rule sets that can be compiled into platform-specific scripts. Each firewall has a target platform (e.g. iptables or nftables) and a host operating system.

Cluster
   A **cluster** groups multiple firewall objects into a high-availability (HA) configuration. The configuration is defined once on the cluster and automatically compiled for each member firewall. Cluster interfaces can include failover groups (e.g. for VRRP) and state synchronization groups (e.g. for conntrack).

Interface
   An **interface** represents a network interface on a device (e.g. ``eth0``, ``lo``, ``br0``). Interfaces hold the IP addresses assigned to them and can have sub-interfaces for VLANs, bonding slaves, or bridge ports.


Addresses
---------

Address objects represent network endpoints used in firewall rules.

IPv4 / IPv6
   A single host address.

Network / Network IPv6
   A network defined by an address and a netmask (e.g. ``192.168.1.0/24``).

Address Range
   A contiguous range of IP addresses defined by a start and end address.

Address Table
   A list of addresses loaded from an external file. Address tables can operate in two modes: at compile time (addresses are expanded inline into the generated rules) or at run time (the file is read when the firewall script executes, using ipset for efficient matching).

DNS Name
   An object resolved via DNS lookup. Like address tables, DNS names can be resolved at compile time or at run time, allowing dynamic IP updates.

Physical Address
   A MAC (hardware) address.


Services
--------

Service objects define network protocols and ports used in firewall rules.

TCP Service / UDP Service
   A service defined by source and/or destination port ranges, optionally with TCP flag matching.

ICMP Service / ICMPv6 Service
   An ICMP message type and code.

IP Service
   A generic IP protocol identified by its protocol number.

Custom Service
   A platform-specific service definition using raw syntax.

Tag Service
   A service used for packet tagging and marking.


Groups
------

A **group** is a container that holds references to other objects. When used in a rule, a group acts as a shorthand for all its members -- during compilation, groups are expanded recursively into their individual members.

Object Group
   Contains references to address and host objects.

Service Group
   Contains references to service objects.

Interval Group
   Contains references to time interval objects.


Time Intervals
--------------

An **interval** (or time object) defines a recurring schedule during which a rule is active, enabling time-based access control. Rules can be scheduled to apply only during certain hours and days of the week.


Rule Sets and Rules
-------------------

Rule Set
   An ordered collection of rules belonging to a firewall or cluster. Each rule set can be configured to apply to IPv4, IPv6, or both address families.

Rule
   A single entry in a rule set. Each rule references objects in its columns (source, destination, service, interface, time) and specifies an action to take when matched.

Policy
   A rule set containing packet filter rules. Policy rules define what traffic is allowed, denied, or rejected based on source, destination, service, interface, direction, and time. In iptables terms, policy rules compile to the ``filter`` table.

NAT
   A rule set containing Network Address Translation rules. NAT rules translate source and/or destination addresses and ports. Each NAT rule specifies original and translated source, destination, and service. In iptables terms, NAT rules compile to the ``nat`` table.

Routing
   A rule set containing static routing rules. Routing rules define destination networks and gateways, compiling to ``ip route`` commands in the generated script.


Compile and Install
-------------------

Compile
   The process of transforming the abstract, platform-independent firewall rules into a platform-specific script (e.g. an iptables shell script or an nftables configuration). During compilation, groups are expanded, address families are separated, rules are validated, and the output is assembled from configlet templates into a complete script.

Install
   The process of deploying a compiled firewall script to the target machine and activating it. FirewallFabrik uses SSH/SCP to securely transfer the script and execute it on the remote firewall.

Configlet
   A template file used during compilation to generate portions of the final firewall script. Configlets are shell script fragments that are assembled into the complete output. They can be customized by the user to modify the generated scripts.
