Firewall Policies
=================

.. sectnum::
   :start: 1

.. contents::
   :local:
   :depth: 3

This chapter describes working with policies. :doc:`10 - Compiling and Installing` describes compiling and installing a policy.

Policies and Rules
------------------

Each firewall object has several sets of rules associated with it: access policy rules, Network Address Translation (NAT) rules, and routing rules.

* Access policy rules filter traffic, controlling access to and from the firewall machine and the machines behind it. An access policy rule set is sometimes just called a "policy."
* NAT rules describe address and port transformations that the firewall should make to packets flowing through it.
* Routing rules establish static routes in the firewall.

Firewall software varies widely in the way it can process packets. For example, some firewalls perform address and port transformations first and then apply policy rules, while some others do it the other way around. There are many other variations and features specific to particular implementations. In Firewall Builder though, you work with an abstract firewall that looks and behaves the same regardless of the target firewall platform. You can build and install firewall polices for one platform, then switch the target and use the exact same policies to generate rules for an entirely different platform. (This assumes both platforms support the features you need.)

Firewall Builder compensates for differences in implementation between firewall platforms. For example, Cisco PIX applies its access list rules to the packet before it performs address and port transformations according to the NAT rules. As a result, a policy rule that controls access to a server behind the firewall doing NAT should be written using the firewall object instead of the server object. The meaning of such a rule is not obvious at a glance since you have to keep in mind all the NAT rules as well as remember that this policy rule controls access not to the firewall machine, but rather to the server behind it. Firewall Builder takes into account these variations like this by using smart algorithms to transform rules defined in the GUI into rules that achieve the desired effect in the target firewall platform. Using Firewall Builder, you write your rules as if NAT translation happens before the access rules are applied.

Firewall Access Policy Rule Sets
---------------------------------

.. figure:: img/policy-access-policies.png
   :alt: Access Policies

   Access Policies

Access policy rules provide access control because they define which packets are permitted and which are denied. A firewall access policy consists of a set of rules. Each packet is analysed and its elements compared against elements in the rules of the policy sequentially, from top to bottom. The first rule that matches the packet has its configured action applied, and any processing specified in the rule's configured options is performed.

Each rule has a standard set of rule elements against which packet characteristics are compared. These rule elements, displayed as fields in the rule, include the packet's source address (Source), its destination address (Destination), its protocol and port numbers (Service), the interface it is passing through (Interface), its direction of travel (Direction), and the time of its arrival (Time). For example, if a packet entering the firewall has a source address that matches the object in the Source field of the rule, its destination address matches the object in the Destination field, its protocol and port numbers match the object in the Service field, the interface it passes through matches the interface object in the Interface field, its direction matches that specified in the Direction field, and the time of its arrival matches that specified in the Time field, then the firewall takes the actions specified in the Action field and applies the options specified in the Options field. A field where a value of "Any" or "All" is specified is considered to match all packets for that rule element.

For example, in Figure 7.1, rule #0 is "anti-spoofing": it denies all packets coming through the outside interface with source address claiming to be that of the firewall itself or internal network it protects. This rule utilizes interface and direction matching in addition to the source address. Rule #2 says that connection from the internal network (network object **net-192.168.1.0**) to the firewall itself (object **firewall**) using **ssh** is allowed (action **Accept**). The "Catch all" rule #6 denies all packets that have not been matched by any rule above it. The access policy in Figure 7.1 is constructed to allow only specific services and deny everything else, which is a good practice.

By default, a rule matches on specified Source, Destination, and Service rule elements, matching all interfaces and traffic directions. If you want to restrict the effect of the rule to particular interfaces or traffic directions, you must specify the restriction in the rule.

Source and Destination
~~~~~~~~~~~~~~~~~~~~~~

The Source and Destination rule elements allow you to match a packet to a rule based on the packet's source and destination IP address.

Configure these rule elements by dragging some combination of addressable objects into the field from the object tree.

* Specify a specific IPv4 address by dragging and dropping an IPv4 address object.
* Specify a specific IPv6 address by dragging and dropping an IPv6 address object.
* Specify all the IP addresses on a host by dragging and dropping a host object.
* Specify a range of IP addresses by dragging and dropping an address range object.
* Specify a particular subnet by dragging and dropping a network object.
* Specify an address configured as DNS "A" record for a given host name by dragging and dropping a DNS name object.
* Specify a set of different object types by simply dragging and dropping multiple addressable objects into the field.
* Define a group object composed of different address objects and drag and drop the group object into the field.

:doc:`05 - Working with Objects` describes how to work with address objects.

In addition, you can exclude, or "negate," a source or destination address by dragging it into the field, then right-clicking and selecting Negate from the context menu. In the example presented in Figure 7.2, the RFC 1918 address range object has been excluded from the rule; as a result, the rule matches any destination address *except* addresses within the private address space.

.. figure:: img/policy-destination-rfc1918.png
   :alt: Destination Matches Any RFC 1918 IP Address

   Destination Matches Any RFC 1918 IP Address

Service
~~~~~~~

The Service rule element matches packets based on the packet's IP service, as defined by protocol and port numbers. To match on a service, drag a service object from the object tree into the Service field. More information on service objects is available in :doc:`05 - Working with Objects`.

As in the Source and Destination rule elements, you can exclude, or "negate" a service by dragging its object to the Service field, then right-clicking and selecting Negate from the context menu.

Interface
~~~~~~~~~

The Interface rule element matches packets based on which firewall interface the packet traverses. (Note that this rule element refers to firewall interfaces, not host interfaces.) By default, all rules created in Firewall Builder affect all firewall interfaces. (This is true in all target platforms.) For cases where you want a rule to match on only a particular interface or set of interfaces, you can drag a firewall interface object or set of firewall interface objects into the field.

Direction
~~~~~~~~~

The Direction rule element matches the direction a packet is travelling as it traverses the interface. There are three traffic direction settings for policy rules:

* A direction of Inbound matches traffic that is ingressing through a firewall interface.
* A direction of Outbound matches traffic that is egressing through a firewall interface.
* A direction of Both matches traffic either ingressing or egressing from the firewall. When you use the Both direction in a rule and compile the rule, Firewall Builder converts the rule into two rules: one for direction Inbound and one for direction Outbound. Firewall Builder then validates each rule to make sure they both make sense by looking at the defined source and destination addresses, dropping one of the rules if necessary.

If you build a rule with a firewall object in the Destination field and with direction of Both, the result for PF platforms should be a rule with **pass in**, which is equivalent to a direction of Outbound in the original Firewall Builder rule. For iptables platforms, the rule is placed in the **INPUT** chain. If the firewall object is defined in the Source field of the rule, then Firewall Builder automatically changes the direction Both to Outbound and processes the rule accordingly.

This automatic change of the direction is only performed when the direction is Both. If the direction is Inbound or Outbound, Firewall Builder complies with the setting without changing the rule. (This is how anti-spoofing rules are constructed, for example, because in rules of that kind, the firewall object and the objects representing addresses and networks behind it are in the Source field, yet the direction must be set to Inbound.)

Note that traffic direction is defined with respect to the firewall device, not with respect to the network behind it. For example, packets that leave the internal network through the firewall are considered "inbound" on firewall's internal interface and "outbound" on its external interface. Likewise, packets that come from the Internet are "inbound" on the firewall's external interface and "outbound" on its internal interface. Figure 7.3 illustrates directions for packets entering or exiting the firewall interface.

.. figure:: img/policy-traffic-directions.png
   :alt: Traffic Directions

   Traffic Directions

Many supported firewall platforms allow for rules to be written without explicitly specifying a direction of "in" or "out"; for example, **pass quick proto tcp ...** in PF configuration or iptables rules in the **FORWARD** chain without the **-i interface** or **-o interface** clauses. Firewall Builder always tries to use this construct for rules with direction Both, unless addresses in the source and destination indicate that the rule can be made more specific.

.. figure:: img/policy-modifying-direction.png
   :alt: Modifying the Direction of a Policy Rule

   Modifying the Direction of a Policy Rule

Action
~~~~~~

The Action is the action taken on a rule that matches on the Source, Destination, Service, Interface, Direction, and Time fields.

The policy rule action can be any of the actions types listed below. Not all firewalls support every action; however, Firewall Builder is aware of the capabilities of each platform and allows only the options valid for the specified firewall target. Note also that the same action may be referred to by a different name on different target platforms.

Some actions have parameters. For these actions, Firewall Builder opens the action dialog when you select the action for you to specify the setting. To change the parameter setting for an existing action, double-click the action icon in the Action field or right-click it and select Parameters from the context menu. This opens the dialog for the action, where you can change the parameter setting.

* **Accept**: Allows the packet through the firewall. No subsequent rules are applied. This action has no parameters.

* **Deny**: Silently drops the packet. No subsequent rules are applied. This action has no parameters.

* **Reject**: The packet is dropped and the firewall reacts to the packet in the way you specify; for example, the firewall can send a TCP RST message or one of a number of ICMP messages. No subsequent rules are applied. This action has one parameter: when you select Reject as the action, the action dialog automatically opens for you to specify the response to be sent. Figure 7.5 shows the supported responses for the Reject action.

.. figure:: img/policy-reject-action-responses.png
   :alt: Responses for the Reject Action

   Responses for the Reject Action

* **Accounting**: Counts packets matching the rule, but makes no decision on the packet. Even if the packet matches, the inspection process continues with subsequent rules. For iptables this action has one parameter which is the name of the rule chain that will be created. Traffic that matches this rule will have a target of the defined accounting user chain. In this case the traffic is neither accepted nor denied, so in order for the traffic to be passed through the firewall another rule must be defined with the Action set to Accept.

* **Queue**: Supported only for iptables and ipfw target platforms. Passes the packet to a user-space process for inspection. It is translated into **QUEUE** for iptables and the **divert** for ipfw. This action has no parameters.

* **Custom**: Supported for iptables, ipf, and ipfw target platforms. Allows you to specify an arbitrary string, for example defining iptables module 'recent' parameters as shown in :doc:`05 - Working with Objects`. This action has one parameter: when you select Custom as the action, the action dialog automatically opens for you to specify the custom string.

* **Branch**: Supported only for iptables and PF target platforms, which provide suitable syntax for allowing control to return to the higher-level rule set if the branch cannot make a final decision about the packet. Used to branch to a different rule set. For iptables, this action is translated into a user-defined chain. The name of the chain is the name of the Policy rule set object that the branch jumps to. For PF, this action is translated into an anchor with the same name as the Policy rule set that the branch jumps to. This action has one parameter: when you select Branch as the action, the action dialog automatically opens for you with a drop area to drag-and-drop the Policy rule set which will be branched to.

* **Continue**: Continue is, essentially, an empty action. You can use this option when you want to assign an option, such as logging or packet marking, to a matched packet but take no other action in that rule. This action has no parameters. On iptables systems, using just the Continue action results generates a rule that has no **-j** target defined. If the action is set to Continue and the logging option has been applied, the generated rule has the **-j LOG** target set.

.. figure:: img/policy-rule-actions.png
   :alt: Rule Actions

   Rule Actions

Policy actions can be combined with rule options specified in the Options rule element to have the firewall perform multiple operations within a single rule. For example, you can tag, classify, and accept a packet within a single rule by setting the Tag and Classify options and setting the action to Accept. For more information on configuring policies to perform multiple operations, see `Configuring Multiple Operations per Rule`_.

Time
~~~~

The Time rule element allows you to restrict a match to a particular time interval. To match against a particular time, define a time interval object as described in :doc:`05 - Working with Objects` and drag the time interval object into the Time rule element.

Options and Logging
~~~~~~~~~~~~~~~~~~~

The Options rule element allows you to enable and disable logging, set logging values, and set certain options (such as tagging and classifying) to be applied when a packet matches the rule. Not all firewalls support all log settings or a full set of options; however, Firewall Builder is aware of the capabilities of each platform and shows only the options valid for the specified firewall target. Note that options apply only to the current rule.

The right-click Options context menu contains three selections:

* **Rule Options**: Opens the Options dialog, which allows you to set logging values and supported options for the current rule. The options and log settings available vary with the target platform.
* **Logging On**: Enables logging for packets matching this rule. If the target firewall platform does not support selective logging of packets, log settings are disabled in the Options dialog.
* **Logging Off**: Disables logging for packets matching this rule. If the target firewall platform does not support selective logging of packets, this menu item is disabled.

At the bottom of the context menu, the Compile Rule selection allows you to perform quick rule compilation.

Rule options may include the following, depending on the target platform:

* **General**: Depending on the target platform, general settings may include whether inspection should be stateless rather than stateful (for some targets, state tracking options are located on a Stateless or State Tracking tab), sending ICMP "Unreachable" packets masquerading as being from the original destination, keeping information on fragmented packets to be applied to later fragments, and/or whether to assume that the firewall is part of the "any" specification.

* **Logging**: Depending on the target platform, log settings may include the log level, logging interval, log facility, log prefix, the Netlink group, and/or a checkbox to disable logging for the current rule.

* **Route**: Supported only for ipfilter and PF targets. For iptables, this option is deprecated. Directs the firewall to route matching packets through a specified interface. For PF and ipfilter, you can specify the interface and next hop. This information is translated into the **route** option. You can also specify whether to reroute the packet, reroute the reply to the packet, or make the changes to a copy of the packet, allowing the original packet to proceed normally. This information is translated into the **route-to**, **reply-to**, and **dup-to** options, respectively. The PF platform also supports a fast-route option, translated as the **fastroute** option, and supports selecting from a set of load-balancing algorithms.

* **State Tracking**: Allows you to specify a number of options for tracking the progress of a connection. Keeping state can help you develop rule sets that are simpler and result in better packet filtering performance. For iptables, ipfilter, and ipfw target platforms, this option allows you to make packet inspection to be stateless rather than stateful, which is the default. (For these platforms, this option is located on the General tab.) PF targets support a number of additional state tracking settings. The **Force "keep state"** setting directs the firewall to make a state entry even if the default for the rule is to be stateless. The **Activate source tracking** setting enables tracking the number of states created per source IP address. The **Maximum number of source addresses** setting controls the maximum number of source addresses that can simultaneously have state table entries; this is the PF **max-src-nodes** option. The **Maximum of simultaneous state entries** setting controls the maximum number of simultaneous state entries that can be created per source IP address; this is the PF **max-src-states** option. Note that this limit controls only states created by this rule. State tracking is not supported for Cisco FWSM, Cisco Router IOS ACL, or Cisco ASA/Cisco PIX target platforms.

* **Tag**: Supported only for iptables and PF platforms. Associates a tag, or mark, with the packet. When you enable this option, you must specify a TagService object which defines the tag to be applied to matching packets. For iptables, the Tag operation is translated into a **MARK** target with corresponding **--set-mark** parameter and, optionally, additional rule with a **CONNMARK --save-mark** target. If the option that activates the **CONNMARK** target is used, the compiler also adds a rule at the very top of the policy to restore the mark. Rules are placed in the **INPUT**, **OUTPUT**, and **FORWARD** chain of the mangle table, which ensures that DNAT happens before rules in the mangle table interact with the packet. The **PREROUTING** chain in the mangle table is executed before the **PREROUTING** chain in the NAT table, so placing tagging rules in the **PREROUTING** chain would make them fire before DNAT. The **POSTROUTING** chain of the mangle table, as well as its **FORWARD** and **OUTPUT** chains, work before corresponding chains of the NAT table. In all cases, the goal is to make sure DNAT rules process the packet before, and SNAT rules process the packet after, filtering and tagging rules. For PF, this option is translated into the **tag** option.

* **Classify**: Supported only for iptables, PF, and ipfw. Allows the firewall to define a QoS class for the packet that matches the rule. It is translated into **CLASSIFY** for iptables, with the **--set-class** parameter. For PF, it is translated into **queue**. The compiler for ipfw can use **pipe**, **queue**, or **divert**, depending on how the action is configured in Firewall Builder. When you enable this option, you must specify a Classify string.

* **limit**: Supported only for iptables. Implements the iptables **limit** module, directing the firewall to perform rate-limiting on the connection. This option is useful for preventing, for example, TCP SYN flood attacks. You specify the maximum average matching rate; this translates into the iptables **--limit rate** option, limiting incoming connections once the limit is reached. You can also specify a burst level; this is the maximum initial number of packets to match. The burst number is incremented by one every time the rate-limit is not reached, up to this number; this value translates into the iptables **--limit-burst** option. You can also reverse the meaning of the rate-limit rule (that is, accept everything above a given limit) by checking the Negate checkbox.

* **connlimit**: Supported only for iptables. Implements the iptables **connlimit** module, directing the firewall to restrict the number of parallel TCP connections for this source/destination pair. You specify the maximum number of existing parallel connections; this translates into the iptables **--connlimit-above** option. You can also specify a network mask to limit the number of connections to networks of a particular size; this value translates into the iptables **--connlimit-mask** option. You can reverse the meaning of the connection-limiting rule (that is, accept everything above a given limit) by checking the Negate checkbox.

* **hashlimit**: Supported only for iptables. Implements the iptables **hashlimit** module. The hashlimit matching option is similar to the rate-limiting option, implemented per destination IP or per destination-IP/destination-port tuple. You must provide a name for this hash-limiting entry, specify the rate and burst level. You can also select the mode of the module, which specifies whether to match on IP address alone (**srcip** or **dstip**) or on an address/port combination (**srcport** or **dstport**). The **htable-size** setting controls the number of buckets of the hash table. The **htable-max** setting controls the maximum number of entries in the hash table. The **htable-expire** setting controls the interval (in milliseconds) after which a hash entry expires. The **htable-gcinterval** setting controls the interval (in milliseconds) between garbage collection operations. On some older iptables systems, this module is named **dstlimit**. If your target platform is one of these systems, check the checkbox.

* **Mirror rules**: Supported only for Cisco Router IOS ACL. Directs the compiler to create a rule reversing the specified source and destination address and service fields, which can be used to match "reply" packets for address and service characteristics in packets matched by this rule. Detailed information about mirror rule settings is provided in the Rule Options dialog for this platform.

Figure 7.7 shows the Tag tab of the Options dialog for the **iptables** platform.

.. figure:: img/policy-iptables-options-dialog.png
   :alt: iptables Options Dialog

   iptables Options Dialog

If the options of a particular rule have been changed from their default values, an icon appears in the Option field for that rule. Keep in mind that not all rules have the same default options. For example, by default a Deny rule is stateless, because there is no reason to keep state on a connection that won't be allowed. So, if you turn on state for a Deny rule, you'll see the icon. An Accept rule, on the other hand, has the opposite behavior. By default, state is kept for Accept rules, so no icon appears when state is on. In other words, if you turn state keeping off, then if you change the default behavior for that rule, the icon is displayed.

You can set multiple options and combine them with the policy's action so that the firewall performs multiple operations within a single policy rule. For example, where supported, you can tag, classify, and accept a packet within a single rule by configuring the Tag and Classify options and setting the action to Accept. For more information on configuring policies to perform multiple operations, see `Configuring Multiple Operations per Rule`_.

Working with Multiple Policy Rule Sets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Every firewall object created in Firewall Builder begins with a single policy rule set. For many firewalls, this is all you need. However, Firewall Builder allows you to create multiple access policy rule sets for a single firewall object and, if your platform supports it, branch between the rule sets. This can help you modularize your policy.

In the following example, the firewall object "fw" has three policy rule sets: **Policy**, **Policy_2**, and **mgmt**:

.. figure:: img/policy-multiple-rule-sets.png
   :alt: Firewall with Multiple Policy Rule Sets

   Firewall with Multiple Policy Rule Sets

To create an additional rule set, right-click the firewall object in the tree and select Add Policy Rule Set from the context menu.

All policy rule sets have configurable parameters. To see a policy rule set's parameters, open it in the editor by double-clicking it in the tree.

.. figure:: img/policy-rule-set-dialog-iptables.png
   :alt: Policy Rule Set Dialog (iptables)

   Policy Rule Set Dialog (iptables)

This dialog has a Name, IPv4/IPv6 setting and a Top ruleset checkbox. For iptables firewalls, there is also a pair of radio buttons that indicates whether the policy should affect filter+mangle tables or just mangle table.

The IPv4/IPv6 pull-down menu lets you select whether the rule set should be compiled for IPv4 only (ignoring any IPv6-related rules), IPv6 only (ignoring any IPv4-related rules), or for both IPv4 and IPv6. If both IPv4 and IPv6 are selected, the compiler automatically places each rule into the correct part of the configuration.

When multiple rule sets have been defined, one rule set is tagged as the "top" rule set by checking the Top rule set checkbox when the rule set is added. The top rule set is the primary rule set assigned to the device. Only one rule set of each type can be marked as the top rule set. The top rule set is always used (if it has any rules). Other rule sets are only used if they are the targets of branching. Scripts are generated as follows for target platforms.

* **iptables**: Rules defined in the top rule set are placed into the built-in INPUT, OUTPUT, and FORWARD chains. Rules defined in rule sets where the Top rule set checkbox is not checked are placed into a user-defined chain with the same name as the rule set.
* **PF**: Rules defined in rule sets other than the top rule set are placed into an anchor with the name of the rule set.
* **Cisco IOS ACLs**: If the rule set is not the top rule set, rules are placed into an access list and the rule set name is prefixed to the access list name; this access list is not assigned to interfaces using the **ip access-group** command. Top rule sets generate ACLs with names consisting of a shortened interface name plus traffic direction. Only these lists are assigned to interfaces.

You fork processing between rule sets using the Branch rule action. In the example, this rule causes packets headed for the **fw-mgmt** host to be passed to the **mgmt** rule set.

.. figure:: img/policy-passing-packet-to-mgmt.png
   :alt: Passing a Packet to the 'mgmt' Rule Set

   Passing a Packet to the 'mgmt' Rule Set

A packet directed to the **mgmt** rule set leaves the main rule set and begins matching against rules in the **mgmt** rule set. If it matches in the **mgmt** rule set, then the specified action is taken. If it does not match in the **mgmt** rule set, processing is passed back to the calling rule set.

Network Address Translation Rules
----------------------------------

.. note::

   As with access policy rule sets, you can create multiple NAT rule sets. However, in older versions of Firewall Builder, it was not possible to branch between rule sets; only the rule set marked as "top" was used in v3.x. Beginning with Release 4.0, Firewall Builder supports building branches in NAT rule sets.

Basic NAT Rules
~~~~~~~~~~~~~~~

Address translation is useful when you need to provide Internet access to machines on the internal network using private address space (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16, as defined in RFC 1918). Private addresses are not routable on the Internet, which means clients out on the Internet cannot connect to servers with private addresses. Conversely, machines on the network using one of these addresses cannot connect to servers on the Internet directly. In order to allow internal machines to establish connections with external machines, the firewall must convert the private addresses to public addresses, and vice versa. In other words, the firewall must perform Network Address Translation (NAT). In Firewall Builder, NAT rules are added in the NAT rule set, located under the firewall object in the tree.

.. figure:: img/nat-rule-set.png
   :alt: NAT Rule Set

   NAT Rule Set

.. figure:: img/nat-translation-rules.png
   :alt: Network Address Translation Rules

   Network Address Translation Rules

As in firewall policies, NAT rules are inspected by the firewall in the order they appear in the policy. Each NAT rule consists of the following rule elements:

* **Original Src** -- An address object to compare to the source address of the incoming packet.

* **Original Dst** -- An address object to compare to the destination address of the incoming packet.

* **Original Srv** -- One or more service objects to compare to the packet's service.

* **Translated Src** -- If the original source, destination, and service all matched, this object becomes the new source address of the packet.

* **Translated Dst** -- If the original source, destination, and service all matched, this object becomes the new destination address of the packet.

* **Translated Srv** -- If the original source, destination, and service all matched, this object becomes the new service (port number) of the packet.

* **Interface In** -- The inbound interface for the NAT rule. On iptables systems this will result in the ``-i`` parameter being set. The default is Auto, which means Firewall Builder will attempt to determine the appropriate interface(s) the rule should include. This option is available in Firewall Builder Release 4.2 and later.

* **Interface Out** -- The outbound interface for the NAT rule. On iptables systems this will result in the ``-o`` parameter being set. The default is Auto, which means Firewall Builder will attempt to determine the appropriate interface(s) the rule should include. This option is available in Firewall Builder Release 4.2 and later.

* **Options** -- This field lets you specify platform-specific options for the packet. Right-click in the field and select Rule Options to see options for your platform. Click Help in the Options dialog to see help for available parameters for your platform. See `Options and Logging`_ for more information.

* **Comment**

Here is how it works:

The original packet is compared with NAT rules, one at a time, starting with the topmost rule. Once a rule that matches a packet's source address, destination address and service is found, the firewall takes parameters from the second half of that rule and makes the indicated substitutions. Some rule elements in the first half of the rule may be set to match "any", which means that that element matches no matter what is in the packet. Some rule elements in the second half of the rule may be set to *original*, which means that parameter is not changed even if the rule matches. (No substitution happens for that element.)

In addition to making the substitution, the firewall also makes a record in its internal table of the original and modified values. The firewall uses this information to perform a reverse translation when the reply packet comes back.

The NAT rules in the screenshot (Figure 7.12) tell the firewall to do the following:

* **Rule #0:** If the original packet originated on the internal subnet 192.168.2.0/24 and is destined for the internal subnet 192.168.1.0/24, then there is no need to translate the packet.

* **Rule #1:** If a packet is headed to the Internet from either the 192.168.2.0/24 or 192.168.1.0/24 subnet, then the source IP address should be set to the IP address of the firewall's "outside" interface.

* **Rule #2:** If any packet was originally destined for the "outside" interface on the firewall, the destination IP address should be rewritten to be the IP address of the "server on dmz" host IP (in this case, 192.168.2.10).

Some firewall platforms support negation in NAT rules. If it is supported, this feature can be activated by right-clicking the rule element in the NAT rule. See `Support for Rule Elements and Features on Various Firewalls`_ for information on what firewall platforms support negation in NAT.

You can create NAT rules and edit them using the same methods as described in `Editing Firewall Rule Sets`_.

Source Address Translation
~~~~~~~~~~~~~~~~~~~~~~~~~~

Using NAT to translate private IP addresses to public, and vice versa, is often called "masquerading". When configured this way, the firewall rewrites the source IP address of each packet sent by internal machines to the Internet, replacing the private IP address with the address of its external interface.

In Firewall Builder, this type of NAT rule is composed as shown in Rule 1 in Figure 7.12.

In this rule, objects representing internal networks are placed in Original Src and the firewall's outside interface object is placed in Translated Src, indicating that we want the source address of the packets to be translated. As before, we do not need to worry about reply packets, because the underlying firewall software keeps track of translations done for all the connections opened through the firewall and rewrites addresses in all reply packets automatically.

In Figure 7.12, Rule 1 uses the firewall interface object in the Translated Src, which means the source address of the packet will be substituted with the address of firewall outside interface. If there is more than one external interface, the decision of which interface to use is made by the firewall's routing table.

One of the consequences of this design is that rule #1 on Figure 7.12 provides translation for packets coming from internal subnets going out to the Internet.

.. note::

   Interface object can be used in the NAT rules even if the address of this interface is obtained dynamically and is not known beforehand.

.. figure:: img/nat-source-translation-directions.png
   :alt: Translations done to packets going in different directions

   Translations done to packets going in different directions: (A) when firewall object is used in TSrc in the NAT rule; (B) when interface eth1 is used in TSrc in the NAT rule; (C) when host object with address 192.0.2.50 is used in TSrc in the NAT rule

Examples of Source Address Translation Rules
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This section demonstrates examples of NAT rules that manipulate the source address and ports of packets.

Basic Source Address Translation Rule
'''''''''''''''''''''''''''''''''''''

Source address translation is useful when you need to let machines using private address space (for example, as defined in RFC 1918) access the Internet. The firewall manipulates the source address of IP packets to make them appear to come from one of the public addresses assigned to the firewall instead of coming from the actual, private address on the internal network.

In the following examples we will use a firewall object configured as follows:

.. figure:: img/nat-firewall-object-details.png
   :alt: Firewall object with eth0 interface details

   Firewall object with eth0 interface details

The external interface of the firewall is *eth0*, it has a static IP address 192.0.2.1 (this is an example address, normally external interface would have a publicly routable address).

The simplest source address translation rule looks like this:

.. figure:: img/nat-basic-snat-rule.png
   :alt: Basic source address translation rule

   Basic source address translation rule

We put the interface of the firewall into Translated Src and an object representing the internal network in the Original Src element of the rule. This tells the firewall to replace the source address of packets that match the "Original" side of the rule with the address of the interface *eth0*.

This rule translates into the following simple iptables command:

.. code-block:: text

   # Rule 0 (NAT)
   #
   $IPTABLES -t nat -A POSTROUTING -o eth0  -s 172.16.22.0/24  \
       -j SNAT --to-source 192.0.2.1

Note that Firewall Builder uses the chain *POSTROUTING* for the source address translation rules. It will use *PREROUTING* for the destination translation rules.

For PF, Firewall Builder uses *nat* rule:

.. code-block:: text

   # Rule  0 (NAT)
   #
   nat on en0 proto {tcp udp icmp} from 172.16.22.0/24 to any -> 192.0.2.1

Finally, for PIX, Firewall Builder knows to use global pool in combination with the "nat" command and automatically determines which interfaces to associate ``global`` and ``nat`` commands with:

.. code-block:: text

   ! Rule  0 (NAT)
   !
   global (outside) 1 interface
   access-list id43442X30286.0 permit ip 172.16.22.0 255.255.255.0   any
   nat (inside) 1 access-list id43442X30286.0 tcp 0 0

Note that the generated PIX configuration has been optimized and the "global" command takes address from the interface "outside" regardless of how this address is assigned, statically or dynamically.

Source Address Translation Using Interface with Dynamic Address
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

The generated configurations in the previous examples used the IP address of the external interface for translation. Let's see what configuration Firewall Builder will produce if the external interface has a dynamic address that is not known at the time when configuration is generated.

.. figure:: img/nat-dynamic-interface-config.png
   :alt: Dynamic interface configuration

   Dynamic interface configuration

The NAT rule looks exactly the same as in examples above: we still put interface *eth0* in Translated Src even though its address is unknown.

iptables uses target MASQUERADE when the source NAT is requested with a dynamic interface. Firewall Builder generates the following command:

.. code-block:: text

   # Rule 0 (NAT)
   #
   $IPTABLES -t nat -A POSTROUTING -o eth0  -s 172.16.22.0/24 -j MASQUERADE

PF supports special syntax for the dynamic interface, *(en0)*, which makes it take the address of the interface automatically:

.. code-block:: text

   # Rule  0 (NAT)
   #
   nat on en0 proto {tcp udp icmp} from 172.16.22.0/24 to any -> (en0)

There is no difference in the generated PIX configuration because fwbuilder optimizes it and uses the "global (outside) 1 interface" command which takes the address from the outside interface regardless of whether the address is assigned statically or dynamically.

Port Translation
''''''''''''''''

Firewall Builder can generate configurations for the NAT rules that manipulate not only addresses, but also ports and port ranges. Consider this hypothetical example where we want to squeeze a source port range from the whole unprivileged range 1024 - 65535 to the rather limited range 10000 - 20000 on all connections from internal network to the server on the DMZ:

.. figure:: img/nat-port-translation-rule.png
   :alt: Port translation NAT rule

   Port translation NAT rule

TCP Service object "sport range 10000-20000" is defined as follows:

.. figure:: img/nat-tcp-service-sport-range.png
   :alt: TCP Service object with source port range 10000-20000

   TCP Service object with source port range 10000-20000

For iptables, Firewall Builder generates the following command for this rule:

.. code-block:: text

   # Rule 0 (NAT)
   #
   $IPTABLES -t nat -A POSTROUTING -o eth+  -p tcp -m tcp  -s 172.16.22.0/24 \
       --sport 1024:65535  -d 192.168.2.10 -j SNAT --to-source :10000-20000

This rule matches source port range "1024-65535" and original destination address 192.168.2.10 and only translates source ports to the range 10000-20000. Firewall Builder generated a SNAT rule because the object in the Translated Source requested a change in the source port range. If this object had zeros in the source port range but defined some non-zero destination port range, the program would have generated a DNAT rule to translate destination ports.

Load Balancing NAT Rules
''''''''''''''''''''''''

Many firewall platforms can use NAT to perform simple load balancing of outgoing sessions across a pool of IP addresses. To set this up in Firewall Builder, we start with an address range object:

.. figure:: img/nat-address-range-object.png
   :alt: Address range object for load balancing

   Address range object for load balancing

We then use it in the "Translated Source" of the NAT rule:

.. figure:: img/nat-load-balancing-rule.png
   :alt: Load balancing NAT rule

   Load balancing NAT rule

Here is what we get for the iptables firewall:

.. code-block:: text

   # Rule 0 (NAT)
   #
   $IPTABLES -t nat -A POSTROUTING -o eth+  -s 172.16.22.0/24 \
       -j SNAT --to-source 192.0.2.10-192.0.2.20

In case of PIX, fwbuilder builds complex global pool to reflect requested address range:

.. code-block:: text

   ! Rule  0 (NAT)
   !
   global (outside) 1 192.0.2.10-192.0.2.20 netmask 255.255.255.0
   access-list id54756X30286.0 permit ip 172.16.22.0 255.255.255.0   any
   nat (inside) 1 access-list id54756X30286.0 tcp 0 0

For PF, compiler converted range 192.0.2.10-192.0.2.20 to the minimal set of subnets and produced the following configuration line:

.. code-block:: text

   # Rule  0 (NAT)
   #
   nat proto {tcp udp icmp} from 172.16.22.0/24 to any -> \
       { 192.0.2.10/31 , 192.0.2.12/30 , 192.0.2.16/30 , 192.0.2.20 }

It is possible to use a network object of smaller size in Translated Source which is equivalent to using a small address range:

.. figure:: img/nat-network-object-small.png
   :alt: Network object for load balancing

   Network object for load balancing

We can use it in the rule just like the range object:

.. figure:: img/nat-network-object-in-rule.png
   :alt: Network object used in NAT rule for load balancing

   Network object used in NAT rule for load balancing

This yields for PF:

.. code-block:: text

   # Rule  0 (NAT)
   #
   nat proto {tcp udp icmp} from 172.16.22.0/24 to any -> 192.0.2.0/27

Unfortunately, the smaller network object in Translated Source is not supported for iptables because in iptables, SNAT target can only accept a single IP address or a range of addresses, but not a subnet specification.

PF supports different modes of load balancing for rules like this. To add configuration parameters that control this, open the NAT rule options dialog by double-clicking in the "Options" column of the NAT rule:

.. figure:: img/nat-pf-pool-type-options.png
   :alt: PF pool type options for NAT rule

   PF pool type options for NAT rule

When the "source-hash" option is checked, the generated command becomes

.. code-block:: text

   # Rule  0 (NAT)
   #
   nat proto {tcp udp icmp} from 172.16.22.0/24 to any -> 192.0.2.0/27 source-hash

Destination Address Translation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Suppose we have a network using private IP addresses behind the firewall, and the network contains a server. We need to provide access to this server from the Internet in a such way that connections will be established to the address of the firewall. In this case we need destination address of packets to be rewritten so packets would reach the server on internal network. The simplest rule that translates destination address of incoming packets looks like the one on Figure 7.12, Rule 2.

Basically this rule says "if destination address of the packet matches the external address of the firewall, replace it with the address defined by the object *server on dmz*". If we had used the "firewall" object as the original destination, instead of the interface, then all external interfaces would be mapped to the DMZ server. Figure 7.26 (A) illustrates this. The red, green, and blue packets come to the firewall from different subnets and all have destination addresses that match address of the corresponding interface. If it were not for our NAT rule, packets like that would have been accepted by the firewall and sent to a process expecting them. However, the NAT rule comes to play and changes destination address of all three packets to 10.3.14.100 (the address of server). Packets with this address do not match any address belonging to the firewall and therefore get sent out of the firewall according to the rules of routing.

A rule that does not specify any service for the translation translates addresses in packets of all protocols. This approach can make some rules impractical because they will translate and bounce any packets that are headed for the firewall, making it impossible to connect to the firewall itself using telnet or any other protocol. This is especially inconvenient since, as we saw earlier, translation happens for packets coming from all directions; this means that you won't be able to connect to the firewall even from inside of your network. To alleviate this problem we just add an appropriate service object to the rule as shown in Figure 7.24:

.. figure:: img/nat-http-translation-rule.png
   :alt: Translation Limited to Packets of HTTP Protocol

   Translation Limited to Packets of HTTP Protocol

Rule #0 in Figure 7.24 has limited scope because of the service object "http" in Original Service; it matches and performs address translation only for packets of HTTP protocol, while other packets are processed by TCP/IP stack on the firewall as usual. Very often we only want to translate address for packets coming from particular side of the firewall, typically from the Internet, and do not change other packets. Rule #0 on Figure 7.25 achieves this goal by using firewall's interface object in Original Destination. Only packets with destination address the same as that of interface eth1 of the firewall match this rule and get their address translated. Packets coming from other directions will have different destination address and won't match the rule (see Figure 7.26 (B)).

.. figure:: img/nat-dnat-firewall-interface.png
   :alt: Destination Address Translation Rule Using Firewall Interface

   Destination Address Translation Rule Using Firewall Interface

.. figure:: img/nat-dnat-directions.png
   :alt: Translations done to packets going in different directions

   Translations done to packets going in different directions: (A) when firewall object is used in ODst in the NAT rule and (B) when interface eth1 is used in ODst in the NAT rule

Examples of Destination Address Translation Rules in Firewall Builder
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This section demonstrates examples of NAT rules that manipulate the destination address and ports of packets.

Configuring NAT for the Server using an IP address Belonging to the Firewall
'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

In cases where we have no public IP addresses to spare, we can still use NAT to permit access to the server. In this case, we will use address that belongs to the firewall's external interface. Here is a screenshot showing the firewall object, its interfaces, and an address object that belongs to the external interface:

.. figure:: img/nat-firewall-ip-for-server.png
   :alt: Firewall object with external interface address

   Firewall object with external interface address

We can either use an interface object or a corresponding address object in the rule. The following two examples of rules are equivalent:

Using an interface object:

.. figure:: img/nat-dnat-using-interface.png
   :alt: DNAT rule using interface object

   DNAT rule using interface object

Using an address object:

.. figure:: img/nat-dnat-using-address.png
   :alt: DNAT rule using address object

   DNAT rule using address object

The external interface *eth0* of the firewall has just one IP address; therefore, these two variants of the NAT rule are equivalent.

If the firewall has multiple public IP addresses, then you can add them as additional address objects to the external interface object and then use them in the NAT rules. All address objects attached to an interface are equivalent from a NAT rule standpoint.

Both NAT rules demonstrated in this example provide translation for the destination address of the packet so it can reach the server behind the firewall. We still need a policy rule to actually permit this kind of connection. This rule can be added to the global policy as follows:

.. figure:: img/nat-policy-rule-with-nat.png
   :alt: Policy rule to permit translated traffic

   Policy rule to permit translated traffic

You always need a combination of the NAT rule and a policy rule to do both address translation and then permit the translated packet.

Here is what Firewall Builder generates for iptables using these NAT and policy rules:

.. code-block:: text

   # Rule 0 (NAT)
   #
   $IPTABLES -t nat -A PREROUTING  -p tcp -m tcp -m multiport   -d 192.0.2.1 \
       --dports 21,25 -j DNAT --to-destination 172.16.22.100

   # Rule 0 (global)
   #
   $IPTABLES -A FORWARD  -i + -p tcp -m tcp  -m multiport  -d 172.16.22.100 \
       --dports 21,25  -m state --state NEW  -j ACCEPT

For PF:

.. code-block:: text

   # Rule  0 (NAT)
   #
   #
   rdr on eth0 proto tcp from any to 192.0.2.1 port 21 -> 172.16.22.100 port 21
   rdr on eth0 proto tcp from any to 192.0.2.1 port 25 -> 172.16.22.100 port 25

   # Rule  0 (global)
   #
   #
   pass in quick inet proto tcp  from any  to 172.16.22.100 port { 21, 25 }

These are rather standard destination translation rules. Let's see what Firewall Builder generates for the same rules in the GUI when target firewall platform is set to "PIX":

.. code-block:: text

   class-map inspection_default
     match default-inspection-traffic

   policy-map global_policy
     class inspection_default
       inspect ftp
       inspect esmtp

   service-policy global_policy global

   clear config access-list
   clear config object-group
   clear config icmp
   clear config telnet
   clear config ssh

   object-group service outside.id13228X30286.srv.tcp.0 tcp
    port-object eq 21
    port-object eq 25
    exit

   ! Rule  0 (global)
   !
   !
   access-list outside_acl_in  remark 0 (global)
   access-list outside_acl_in permit tcp any host 172.16.22.100 object-group
       outside.id13228X30286.srv.tcp.0
   access-list inside_acl_in  remark 0 (global)
   access-list inside_acl_in permit tcp any host 172.16.22.100 object-group
       outside.id13228X30286.srv.tcp.0
   access-list dmz50_acl_in  remark 0 (global)
   access-list dmz50_acl_in permit tcp any host 172.16.22.100 object-group
       outside.id13228X30286.srv.tcp.0


   access-group dmz50_acl_in in interface dmz50
   access-group inside_acl_in in interface inside
   access-group outside_acl_in in interface outside

   ! NAT compiler errors and warnings:
   !

   clear xlate
   clear config static
   clear config global
   clear config nat
   !
   ! Rule  0 (NAT)
   !
   !
   access-list id13242X30286.0 permit tcp host 172.16.22.100   eq 21 any
   static (inside,outside) tcp interface 21  access-list id13242X30286.0 tcp 0 0
   access-list id13242X30286.1 permit tcp host 172.16.22.100   eq 25 any
   static (inside,outside) tcp interface 25  access-list id13242X30286.1 tcp 0 0

PIX configuration is considerably more complex. First, protocol inspectors have been activated to set up protocol support. TCP ports were arranged in an object group that is then used in all rules. Access lists were created and attached to all interfaces with "access-group" commands. Destination address translation in PIX configuration is done using "static" commands, which use small access lists to match packets that should be translated. All of this, however, was generated from exactly the same rules and objects in the GUI. All we did is change the firewall platform in the firewall object dialog and make sure network zones and security levels were configured properly. We did not have to configure two interfaces for each NAT rule for PIX: Firewall Builder automatically determined which interfaces it should use for the "static" command.

Configuring NAT for the Server Using a Dedicated Public IP Address
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''

Suppose for some reason you do not want to add an address that should be used for NAT to an interface of the firewall. You can use any address object in the "Original Destination" even if this address object is not attached to the interface of the firewall. The problem with this is that the firewall must "own" public address used for NAT in order for it to answer ARP requests for this address from the upstream routers. If the firewall does not "own" the address and does not answer ARP requests, the router will not know where to send packets with this address in destination. To help you solve this problem, Firewall Builder can automatically add a virtual address to the firewall's interface when you use an address in a NAT rule. This is controlled by a checkbox Add virtual addresses for NAT in the "Script" tab of the firewall's platform "advanced" settings dialog. If this checkbox is turned on, and you use an address object that does not belong to any interface of the firewall, the program adds a code fragment to the generated script to create virtual address of the interface of the firewall to make sure NAT rule will work. If this is not the desired behavior, you can turn this automation off by unchecking this option.

If you use this feature, the NAT rules look exactly the same as shown above, except address objects are taken from the *Objects/Addresses* branch of the tree instead of the interfaces of the firewall. In case of iptables, generated script adds virtual addresses to the firewall with a label that starts with "FWB:" prefix. This helps the script identify and remove addresses it controls when you remove them in Firewall Builder GUI.

NAT Rules Using an Address of Dynamic External Interface
''''''''''''''''''''''''''''''''''''''''''''''''''''''''

In all previous examples, the external interface of the firewall had a static IP address that was used in the destination address translation rules. But what if the address is dynamic and not known at the time when Firewall Builder processes rules? Let's see what happens.

Configuration of objects used in this example:

.. figure:: img/nat-dynamic-external-interface.png
   :alt: Dynamic external interface configuration

   Dynamic external interface configuration

The only difference is that interface *eth0* of the firewall is dynamic and has no IP address. In order to build NAT rules we use this interface in Original Destination (the rule looks exactly the same as rules in the previous examples):

.. figure:: img/nat-dnat-dynamic-rule.png
   :alt: DNAT rule using dynamic interface

   DNAT rule using dynamic interface

Firewall Builder uses the method specific to the target firewall platform that allows it to use an interface with dynamic address in policy and NAT rules. For example, the iptables script generated by Firewall Builder includes a shell function that determines the address of an interface. This function is then used in the generated iptables commands:

.. code-block:: text

   getaddr eth0  i_eth0
   #
   # Rule 0 (NAT)
   #
   $IPTABLES -t nat -A PREROUTING  -p tcp -m tcp  -d $i_eth0 \
       --dport 80 -j DNAT --to-destination 172.16.22.100

For PF, the dynamic interface syntax *(en0)* is used:

.. code-block:: text

   # Rule  0 (NAT)
   #
   rdr on en0 proto tcp from any to (en0) port 80 -> 172.16.22.100 port 80

For PIX, Firewall Builder uses the ``interface`` clause in the ``static`` command which automatically refers to the address of the interface:

.. code-block:: text

   ! Rule  0 (NAT)
   !
   access-list id13242X30286.0 permit tcp host 172.16.22.100  eq 80 any
   static (inside,outside) tcp interface 80  access-list id13242X30286.0 tcp 0 0

Port Translation
''''''''''''''''

Destination port translation allows you to redirect connections arriving at one port to a different port on the internal server. For example, you might want external HTTP connections arriving on port 8080 to be redirected to port 80 on the internal web server. To set this up, we create a TCP service object for port 8080:

.. figure:: img/nat-tcp-service-port-8080.png
   :alt: TCP Service object for port 8080

   TCP Service object for port 8080

We then use it in the NAT rule to translate destination port:

.. figure:: img/nat-port-translation-dnat.png
   :alt: Port translation DNAT rule

   Port translation DNAT rule

For iptables:

.. code-block:: text

   # Rule 0 (NAT)
   #
   $IPTABLES -t nat -A PREROUTING  -p tcp -m tcp  -d 192.0.2.1 \
       --dport 8080 -j DNAT --to-destination 172.16.22.100:80

For PF:

.. code-block:: text

   # Rule  0 (NAT)
   #
   rdr on eth0 proto tcp from any to 192.0.2.1 port 8080 -> 172.16.22.100 port 80

For PIX:

.. code-block:: text

   ! Rule  0 (NAT)
   !
   access-list id13242X30286.0 permit tcp host 172.16.22.100  eq 80 any
   static (inside,outside) tcp 192.0.2.1 8080  access-list id13242X30286.0 tcp 0 0

Routing Ruleset
---------------

Though not strictly a firewall function, Firewall Builder also lets you configure the routing tables of Linux, BSD, Cisco ASA/PIX and Cisco IOS firewalls. Routing rules are ignored for other firewalls.

Construct these rules the same way you construct access policy or NAT rules, by dragging the appropriate objects into the rules. When you run the compiled script on the target firewall, the routing rule set rules create static routes in the firewall.

.. note::

   When executing a firewall script, all existing routing rules previously set by user space processes are deleted. To see which rules will be deleted, you can use the **ip route show** command. All lines not including "proto kernel" will be deleted upon reload of the firewall script.

.. warning::

   RedHat seems to reset routing rules explicitly upon system startup. Therefore, it's hard to distinguish interface routes from routes set up by the user. On RedHat systems, you need to include the interface basic routing rules into your Firewall Builder routing setup.

   **IF YOU DO NOT FOLLOW THIS HINT, YOUR MACHINE WILL FREEZE ANY NETWORK TRAFFIC UPON START OF THE FIREWALL SCRIPT.** This means, for example, if eth0 has network 192.168.3.0/24 attached to it, you need to add a route with Destination=Network(192.168.3.0/24), Gateway empty, and Interface=eth0.

   This problem was encountered on RedHat 8.0, but other versions and distributions might be affected too. (Debian sarge and SuSE Linux work fine without interface routing rules being included in Firewall Builder routing rules.)

If you want to use ECMP (Equal Cost Multi Path) routing rules with your iptables-based firewall, make sure your kernel is compiled with the ``CONFIG_IP_ROUTE_MULTIPATH`` option. See `ECMP routes`_ for instructions on creating multiple paths to a destination.

.. figure:: img/policy-routing-rule.png
   :alt: A Routing Rule

   A Routing Rule

The routing rule contains the following elements:

* **Destination**

  Can be any addressable object (hosts, addresses, address ranges, groups, networks.) The default destination ("Default") is 0.0.0.0/0.

* **Gateway**

  Can be an IP address, an interface, or a host with only one interface.

* **Interface**

  Specify an outbound interface for packets. This interface must be a child interface of the firewall. This option is not available for BSD firewalls.

* **Metric**

  The metric of the route. The default metric for PIX is 1, so a "0" in a rule is automatically changed to 1 at compilation. This option is not available for BSD firewalls.

* **Comment**

  A free-form text field.


Handling of the Default Route
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"Default route" is special in that it is critical for your ability to access the firewall machine when it is managed remotely. To make sure you do not cut off access accidentally by not adding default to the routing rules in Firewall Builder, Firewall Builder treats the default route in a special way.

If the default route is configured in the routing rule set in Firewall Builder, then the default route found in the routing table is deleted and replaced with the one configured in Firewall Builder. However, if there is no default route in the routing rule set in Firewall Builder configuration, then the original default route found in the routing table is not deleted.

Additionally, the script checks if the installation of routing entries was successful and rolls changes back in case of errors. This ensures that the firewall machine will not be left with no default route and therefore no way to access it remotely.


ECMP routes
~~~~~~~~~~~

Firewall Builder supports ECMP routes in Linux-based firewalls using iptables. To create an ECMP rule simply specify several rules with different paths (i.e., different combinations of Gateway and Interface, for the same Destination and with the same metric).

In this example, there are three different paths to HostA.

.. figure:: img/policy-ecmp-routing-rule.png
   :alt: ECMP Routing Rule

   ECMP Routing Rule

Rules are automatically classified in ECMP rules and non-ECMP. The ECMP rules are written out in a separated section of the firewall script after the "normal" routing rules.


Editing Firewall Rule Sets
--------------------------

Adding and Removing Rules
~~~~~~~~~~~~~~~~~~~~~~~~~

.. figure:: img/policy-modifying-rules.png
   :alt: Modifying Policy Rules

   Modifying Policy Rules

Rules can be added, removed, or moved around in the rule set using the Rules menu or the context menu shown in the figure above. To open the context menu, right-click the rule number in the first column of the rule.

Using these functions, you can add new rules above or below the currently selected rule in the policy, remove rules, move the current rule up or down, or use standard copy and paste operations on policy rules. Functions are applied to all selected rules.

The following rule-related functions are available in the Rules menu and the associated right-click context menu:

* **New Group**

  Groups contiguous rules together for easier handling. A group of rules can be collapsed in the display so that only the group name appears. This can make it easier to work with rule sets that have many rules. The New Group command opens a dialog that lets you create and name the new group. The currently selected rule is automatically added to the group. See `Using Rule Groups`_ for information on working with rule groups.

* **Add to the group**

  This context menu selection appears only if you right-click a rule directly above or below an existing group. If selected, the current rule is added to the indicated group. See `Using Rule Groups`_ for information on working with rule groups.

* **Remove from the group**

  The context menu selection appears only if you right-click a rule that is currently in a group. This selection removes the rule from the group. If you remove a rule from the middle of a group, the group splits into two groups, one above and one below the selected rule. Both groups have the same name as the original group. See `Using Rule Groups`_ for information on working with rule groups.

* **Change Color**

  This menu item allows you to assign a color to the rule background. Assigning colors is a good way to group rules visually according to function.

* **Insert Rule**

  Inserts new rule above the current one.

* **Add Rule Below**

  Inserts a new rule below the current one.

* **Remove Rule**

  Removes the selected rule from the rule set.

* **Move Rule Up**

  Moves the selected rule up by one position. The keyboard shortcut is "Ctrl-PgUp" on Linux and Windows or "Cmd-PgUp" on Macintosh. If you select several consecutive rules and use this menu item, all selected rules move together.

* **Move Rule Down**

  Moves current rule down by one position. Keyboard shortcut is "Ctrl-PgDown" on Linux and Windows or "Cmd-PgDown" on Macintosh. If you select several consecutive rules and use this menu item, all selected rules move together.

* **Copy Rule**

  Copies the current rule to the clipboard.

* **Cut Rule**

  Copies current rule to the clipboard and removes it from the rule set.

* **Paste Rule Above**

  Inserts the rule from the clipboard above the current one.

* **Paste Rule Below**

  Inserts the rule from the clipboard below the current one.

* **Disable Rule**

  Marks the rule as disabled; this makes the policy compiler ignore it.

* **Compile rule**

  This menu item compiles the selected rule and shows the result in the editor panel at the bottom of the main window.


Adding, Removing, and Modifying Objects in Policies and NAT Rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To add objects to a policy or NAT rule, you can either drag the objects from the object tree and drop them into the corresponding rule element, or use a copy and paste operation. Objects can be copied into clipboard from the object tree or from another policy rule; in either case, use the right-click context menu or the main menu Edit option.

Right-clicking when the cursor is over the rule elements "Source", "Destination" or "Service" opens a context-sensitive pop-up menu. The same context menu appears when you hover the mouse over the "Original Source", "Original Destination", "Original Service", "Translated Source", "Translated Destination" and "Translated Service" rule elements in a NAT rule.

.. figure:: img/policy-modifying-objects.png
   :alt: Modifying Objects in a Policy Rule

   Modifying Objects in a Policy Rule

This menu provides items for the following functions:

* **Edit**

  This menu item opens the currently selected object in the dialog area.

* **Copy**

  The object is copied into clipboard.

* **Cut**

  The object is copied into clipboard and removed from the rule.

* **Paste**

  The object on the clipboard is pasted into the field in the rule. A copy of the object stays on the clipboard, so it may be pasted multiple times.

* **Delete**

  The object is deleted (actually moved to the "Deleted Objects" library).

* **Where used**

  Opens a dialog that shows a list of where the rule is used in all rule sets in the current firewall. In addition, simply clicking on an object puts a red rectangle around that object everywhere it occurs in the rule set.

* **Reveal in tree**

  Shows the object in its location in the appropriate tree. Simply clicking on the object does the same thing.

* **Negate**

  All objects in the selected rule element are negated. The rule element "Source" is negated in rule #1 in the screenshot above.

* **Compile rule**

  This menu item compiles selected rule and shows the result in the editor panel at the bottom of the main window.


Changing the Rule Action
~~~~~~~~~~~~~~~~~~~~~~~~

To change a rule action, right-click in the Action field and select the new action from the context menu. Depending on the action selected, the Action dialog may open for you to specify parameter settings.

.. figure:: img/policy-changing-action.png
   :alt: Modifying the Action of a Policy Rule

   Modifying the Action of a Policy Rule

Rule actions are described in detail in `Action`_.


Changing Rule Direction
~~~~~~~~~~~~~~~~~~~~~~~

To change the traffic direction for a rule, right-click in the Direction field and select the new direction from the context menu.

.. figure:: img/policy-changing-direction.png
   :alt: Modifying the Direction of a Policy Rule

   Modifying the Direction of a Policy Rule

Traffic directions are described in detail in `Direction`_.


Setting Rule Options and Logging
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To change the options and log settings associated with a rule, right-click in the Options field and select a menu item from the context menu. Enable or disable logging by right-clicking the Options field and selecting Logging On or Logging Off, respectively, from the context menu. Set rule options or change log settings by opening the Options dialog. You can do this by double-clicking within the Options field of the rule or by right-clicking the Options field and selecting Rule Options from the context menu.

.. figure:: img/policy-rule-options-menu.png
   :alt: Rule Options for Policies

   Rule Options for Policies

Rule options and log settings are described in detail in `Options and Logging`_.


Configuring Multiple Operations per Rule
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Suppose you have a scenario where you want the firewall to perform a number of operations on packets that match a particular firewall rule. For example, you might want packets matching the rule to be marked (tagged), classified and then accepted. Instead of defining multiple single-action rules to accomplish this behavior, Firewall Builder allows you to combine a set of rule options with an action in a single rule. The ability to specify multiple operations for a single rule helps keep the number of required rules to a minimum, and keeps your rule set simpler and more readable.

Some target firewall platforms, such as PF, natively support performing multiple operations per rule. Other firewall platforms, such as iptables, do not explicitly support configuring multiple operations per rule. For these platforms, Firewall Builder automatically transforms the configured policy into however many rules are required by the target platform.


Configuring an iptables rule to Accept and Classify
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's look at an example where traffic matching a particular rule, such as the one shown below. This rule matches SSH traffic destined to a specific address.

.. figure:: img/policy-basic-rule-no-options.png
   :alt: Basic rule with no options set

   Basic rule with no options set

The way the rule is currently defined traffic matching the rule will be accepted and no other operations will be performed. However, if in addition to accepting the traffic you also want to classify the traffic into classful qdisc for use with tc, then you need to use the Classify rule option to define the classify value that should be set for traffic matching the rule.

In this example we will use a qdisc value of 1:20 which matches a value configured in tc for prioritizing SSH traffic.

Steps for adding classify string to matching traffic:

1. Right-click on Options section of rule and select Rule Options

2. Click on Classify tab in the Editor panel at the bottom of the screen

3. Enter the value 1:20 in the text box for the Classify string as shown below

.. figure:: img/policy-classify-string-editor.png
   :alt: Entering classify string in Editor panel

   Entering classify string in Editor panel

Notice that the Classify icon and classify string value are now displayed in the rule's Options column. This lets you quickly and easily see what options have been configured for a particular rule.

.. figure:: img/policy-rule-with-classify.png
   :alt: Rule with Classify option set

   Rule with Classify option set

Using the :doc:`10 - Compiling and Installing` feature you can see that this rule will result in the following iptables commands being generated.

.. code-block:: text

   $IPTABLES -A FORWARD -p tcp -m tcp -d 192.168.2.10 --dport 22 -m state --state NEW \
   -j ACCEPT
   # Allow SSH to server
   $IPTABLES -t mangle -A POSTROUTING -p tcp -m tcp -d 192.168.2.10 --dport 22 -m state \
   --state NEW  -j CLASSIFY --set-class 1:20


Configuring a PF rule to Tag packets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this example traffic matching a rule on a PF firewall should be tagged with a tag value that identifies that the traffic is from an internal network that entered the firewall inbound on its internal (em1) network interface.

First, a TagService object needs to be created that will identify the tag value that should be applied to the matching traffic. In this case the tag value will be set to "Internal_Net".

1. In the object tree right-click on the TagServices folder and select New TagService

2. Enter a name for the TagService object

3. Enter the tag value that should be applied, in this case "Internal_Net"

The TagService should look like the figure below.

.. figure:: img/policy-tagservice-settings.png
   :alt: TagService object settings

   TagService object settings

Next, the rule shown below matches the internal network traffic inbound on networking interface em1 needs to be created.

.. note::

   If we set the Action to Accept for this rule the packets will be tagged, but they will also be accepted and no other rules will be processed. To tag the packets, but have the firewall continue processing the packets against additional rules we need to set the Action to Continue.

   Using the Continue action will allow you to define rules farther down in the policy that make use of the tag. Depending on the version of PF that you are using, this will result in either "pass" or "match" rules being generated by Firewall Builder.

.. figure:: img/policy-basic-rule-no-tag.png
   :alt: Basic rule without tag being set

   Basic rule without tag being set

To set the tag value that will be added to packets that match this rule, do the following:

1. Right-click on the Options column of the rule and select Rule Options

2. Click on the Tag tab in the Editor panel at the bottom

3. Drag-and-drop the TagService object created earlier from the object tree to the drop target in the Editor panel as shown below

.. figure:: img/policy-tagservice-in-rule.png
   :alt: Setting the TagService object to use in the rule

   Setting the TagService object to use in the rule

After the TagService object has been added to the rule, the final rule should look like the figure below.

.. figure:: img/policy-completed-tag-rule.png
   :alt: Completed tag rule for PF

   Completed tag rule for PF

Using the :doc:`10 - Compiling and Installing` feature you can see that this rule will result in the following PF command being generated.

.. code-block:: text

   # Tag internal traffic
   pass in on em1 inet from 192.168.1.0/24 to any tag Internal_Net label "RULE 0 --  "

On more recent versions of PF using the Continue Action in a rule will result in the "match" keyword being used. Here's an example of the same rule from above, but with a configuration generated for a firewall that is running PF 4.7.

.. code-block:: text

   # Tag internal traffic
   match in on em1 inet from 192.168.1.0/24 to any tag Internal_Net no state label "RULE 0 -- "


Using Rule Groups
~~~~~~~~~~~~~~~~~

Creating Rule Groups
^^^^^^^^^^^^^^^^^^^^

If you have a rule set with quite a few rules, it can be useful to lump some of them together into rule groups. A rule group is a contiguous set of rules that you have grouped together and assigned a name to. Once you have a group, you can collapse it down visually to save screen real estate, then pop it back open when you need to look inside.

Rule groups *only* affect how the rules are displayed visually. They have *no affect* on how the rule set is compiled or how it works on the firewall.

Let's look at a simple example of using rule groups.

The figure below shows a fragment of a set of rules. There are two rules for packets destined for eth0, several rules for packets destined for eth1, and a couple rules for eth2-destined packets.

.. figure:: img/policy-rules-without-grouping.png
   :alt: Rules without Grouping

   Rules without Grouping

The eth1 rules take up a lot of space, so let's group them together. We can then collapse the group so it uses less space.

To create the group, right-click in the rule number cell of the first "eth1" rule and select New group. (You don't have to click the first rule. Any rule in the group will do.)

.. figure:: img/policy-creating-group.png
   :alt: Creating a Group

   Creating a Group

A dialog appears. Enter the name of the group. This name is for your convenience only, so it can be anything. Here we're naming the group after the interface, but a more descriptive name can be more useful.

.. figure:: img/policy-naming-group.png
   :alt: Naming a Group

   Naming a Group

Now we have a group with one entry. This doesn't provide much value, so let's add other rules to the group. You can add as many rules as you want, but they must all be contiguous in the rule set.

.. figure:: img/policy-group-one-entry.png
   :alt: Group with One Entry

   Group with One Entry

To add more rules, right-click a rule adjacent to the rule in the group, then select Add to the group eth1.

.. figure:: img/policy-adding-to-group.png
   :alt: Adding a Rule to a Group

   Adding a Rule to a Group

Do that to the rest of the "eth1" rows, and we now have a populated group. You can select several consecutive rules and add them to the group at once.

.. figure:: img/policy-group-of-rules.png
   :alt: A Group of Rules

   A Group of Rules

To collapse the group, just click the little minus (-) or a triangle icon (depends on the OS and visual style) in the upper left of the group.

.. figure:: img/policy-collapsed-group.png
   :alt: Collapsed Group

   Collapsed Group

The group now takes up less room on your screen, though it has not changed in function.


Modifying Rule Groups
^^^^^^^^^^^^^^^^^^^^^

You can modify a rule group after you have created it. Options are as follows:

* **Renaming a Group**

  To rename a group, right-click the group name (or anywhere on the gray bar that heads the rule, and select Rename group. Then, change the name in the dialog and click OK.

* **Add more rules to a group**

  You can add an existing rule to a group if the rule is directly above or below the group. Simply right-click the rule and select Add to the group eth1.

* **Remove a rule from a group**

  To remove a rule from the group while leaving it in the rule set, right-click in the number of the rule (left-most column) and select Remove from the group. You can only remove the first or the last rule in the group. Rules in the middle of the group can not be removed from it.

* **Remove a rule completely**

  You can remove a rule in a group entirely by right-clicking the number of the rule (left-most column) and selecting Remove rule. This will remove the rule from the rule set entirely and works the same regardless of whether the rule is a member of a group or not. If you want to move the rule to another part of the rule set, select Cut rule instead, and then paste the rule elsewhere.


Support for Rule Elements and Features on Various Firewalls
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Certain fields in the rules are only available if the target firewall platform supports them. For example, the iptables firewall provides controls for logging of matched packets, while Cisco PIX does not; PIX always logs every packet it drops. Where possible, the policy compiler tries to emulate the missing feature. For example, OpenBSD PF does not support negation natively, but the policy compiler provides a workaround and tries to emulate this feature for PF. Another example is policy rules with "Outbound" direction. Cisco PIX supports only inbound access lists, so the policy compiler emulates outbound Access Lists while generating configuration for PIX. The table below represents a list of fields in the rules and which firewall platforms support them. Information about these fields and features is available for Firewall Builder GUI that disables corresponding menu items and hides associated policy elements when they are not supported.

.. list-table:: Rule Features Available on Different Platforms
   :header-rows: 1
   :widths: 15 8 8 8 8 8 8 10 8 10 10

   * - Firewall Platform
     - Source
     - Destination
     - Service
     - Time Interval
     - Direction
     - Action
     - Logging/Options
     - Comment
     - Negation in Policy rules
     - Negation in NAT rules
   * - iptables
     - \+
     - \+
     - \+
     - \+
     - \+
     - \+
     - \+
     - \+
     - \+
     - \+
   * - ipfilter
     - \+
     - \+
     - \+
     - \-
     - \+
     - \+
     - \+
     - \+
     - \+
     - \-
   * - pf
     - \+
     - \+
     - \+
     - \-
     - \+
     - \+
     - \+
     - \+
     - \+
     - \+
   * - Cisco PIX
     - \+
     - \+
     - \+
     - \-
     - \+
     - \+
     - \-
     - \+
     - \-
     - \-


Compiling and Installing Your Policy
-------------------------------------

See :doc:`10 - Compiling and Installing` for full details on compiling and installing your firewall policy.
