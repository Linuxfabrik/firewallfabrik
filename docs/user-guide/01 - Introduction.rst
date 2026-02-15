Introduction
============

.. sectnum::
   :start: 1

.. contents::
   :local:
   :depth: 2


Introducing FirewallFabrik
--------------------------

FirewallFabrik simplifies firewall policy management for Linux-based firewall platforms, currently supporting Netfilter/iptables and nftables. It provides a professional-grade GUI built with Python and PySide6 (Qt6), making administration tasks straightforward and efficient.

With FirewallFabrik, you can manage the security policy of your firewall efficiently and accurately, without the learning curve usually associated with command line interfaces. Instead of thinking in terms of obscure commands and parameters, you simply create a set of objects describing your firewall, servers, and subnets, and then implement your firewall policy by dragging objects into policy rules. You can also take advantage of a large collection of predefined objects describing many standard protocols and services. Once a policy is built in the GUI, you can compile it and install it on one, or several, firewall machines.

.. figure:: img/firewall-builder-main-window.png
   :alt: FirewallFabrik Main Window


Overview of FirewallFabrik Features
------------------------------------

FirewallFabrik helps you write and manage configuration for your firewalls. It generates iptables shell scripts and nftables configurations for you. You can then deploy the generated scripts manually, through your existing automation (Ansible, CI/CD pipelines), or using the built-in installer. FirewallFabrik provides search functions and full undo/redo history. It allows you to reuse the same address and service objects in the rules of many firewalls. It simplifies coordinated changes of the rules and helps avoid errors in generated configurations.

FirewallFabrik can generate *iptables* and *nftables* configurations. You do not have to remember all the details of their syntax and internal operation. This saves time and helps avoid errors.

Rules built in the GUI look exactly the same and use the same set of objects describing your network regardless of the actual firewall platform you use. You only need to learn the program once to be able to build or modify configuration for iptables or nftables.

Configuration files for the target firewall are auto-generated, so they don't have syntax errors and typos. FirewallFabrik has information about features and limitations of supported firewall platforms. This means you can detect errors before you actually enter commands on the firewall, when it is too late. FirewallFabrik helps you avoid many types of errors at the earliest opportunity; for example, it can detect rule shadowing, a common cause of errors in the policy structure.

Create an object to represent your network, a server, or service once and use it many times. Port number or address changes? No need to scan all the rules of all firewalls to find them. Just change them in the object, recompile, push updated configuration, and you are done. At the same time, the GUI provides *powerful search functions* that help you find all the rules of all firewalls that use some object and perform *search and replace* operations.

If you work for a large distributed organization with many administrators, you can organize address and service objects that describe your network into libraries for easy reuse across firewalls.

FirewallFabrik makes it easy to add IPv6 rules to your existing firewall policies. Create objects describing your IPv6 network, add them to the same rule set that defines your security policy for IPv4, and configure it as a "mixed IPv4+IPv6 rule set". The program generates two configurations, one for IPv4 and another for IPv6, using correct objects for each. There is no need to maintain two policies in parallel for the transition from IPv4 to IPv6.

FirewallFabrik has been designed to manage both *dedicated remote firewalls* and *local firewall configurations* for servers, workstations, and laptops.

FirewallFabrik can generate scripts that set up *interfaces*, *IP addresses*, and other aspects of the general configuration of the firewall machine using configlet templates.

The built-in policy installer uses SSH for a secure communication channel to each firewall and has many safeguards to make sure you never cut yourself off from a firewall in case of a policy mistake. The policy installer can deploy to one firewall or to many firewalls in a batch.


Firewall Policy as Code
-------------------------

FirewallFabrik uses a human-readable YAML file format (``.fwf``) that works well with version control systems like Git. This makes it straightforward to adopt an Infrastructure as Code workflow for your firewall management:

* **Version control**: Store your ``.fwf`` files in a Git repository to maintain a full history of every policy change, including who changed what and when.
* **Peer review**: Use merge/pull requests to have policy changes reviewed by a colleague before they are deployed.
* **Automated deployment**: Integrate the compiled firewall scripts into your existing automation -- whether that is an Ansible playbook, a CI/CD pipeline (GitLab CI, GitHub Actions, Jenkins), or a simple shell script.
* **Reproducibility**: Because the generated ``.fw`` script is deterministic, you can rebuild the exact same firewall state from the source ``.fwf`` file at any time.

Even if you start with a simple manual workflow (edit, compile, scp, activate), the YAML-based format makes it easy to evolve toward a fully automated deployment pipeline as your environment grows.


File Formats
------------

FirewallFabrik uses its own YAML-based file format (``.fwf``) for storing firewall configurations. This format is human-readable, diff-friendly, and works well with version control systems like Git.

For users migrating from Firewall Builder, FirewallFabrik can import existing Firewall Builder XML files (``.fwb``) directly. When saving, the data is always written in the new ``.fwf`` format.

Internally, FirewallFabrik loads all data into an in-memory SQLite database (via SQLAlchemy) for fast querying and editing, with full undo/redo support through database snapshots.


Heritage
--------

FirewallFabrik is built on a long and proven history. It is a modernized port of `Firewall Builder <http://sourceforge.net/projects/fwbuilder>`_, a well-established firewall configuration tool registered on SourceForge since 2000 that has gone through several major releases.

FirewallFabrik carries this project forward into the modern world. Its core concepts and ideas have been preserved and systematically evolved -- including a transition from C++ to Python, from Qt5 to Qt6, from XML to YAML, and toward a more contemporary architecture overall.

While FirewallFabrik is an independent project, it clearly stands on the shoulders of Firewall Builder. The majority of the credit and historical merit therefore belongs to this outstanding tool and its original developers.


How FirewallFabrik Compares to Other Tools
------------------------------------------

If you are evaluating FirewallFabrik for your environment, it helps to understand how it differs from other popular firewall management tools. FirewallFabrik is a **centralized firewall policy design, compilation, and audit tool**. It does not run on the firewall itself -- it models your network objects in a database, lets you design and review rules in a desktop GUI, and then compiles them into deployment-ready configurations for your firewalls.

This is a fundamentally different approach from tools like UFW, firewalld, pfSense, or OPNsense. Crucially, FirewallFabrik is not a replacement for deployment tools like Ansible or Terraform -- it **complements** them. FirewallFabrik produces the shell scripts; your existing automation pipeline deploys them. The following comparisons help you decide whether FirewallFabrik is the right fit for your use case.


vs. UFW
^^^^^^^

UFW ("Uncomplicated Firewall") is a simple command-line interface for managing firewall rules on a single Linux host. It is designed for quick, straightforward setups like ``ufw allow 22/tcp``.

.. list-table::
   :header-rows: 1
   :widths: 25 37 38

   * - Aspect
     - FirewallFabrik
     - UFW
   * - Approach
     - Offline compiler generating shell scripts
     - Live CLI running on the firewall
   * - Clustering
     - Failover groups, state sync (conntrackd)
     - No
   * - Custom chains
     - Automatic and user-defined branching
     - No
   * - IPv6
     - Full dual-stack compilation
     - Supported but basic
   * - Multi-firewall
     - Yes -- single database, many firewalls
     - No -- per-host only
   * - NAT
     - Full SNAT, DNAT, Masquerade, Redirect, Load Balancing, SDNAT
     - Manual editing of ``before.rules``
   * - Object model
     - Rich: hosts, networks, groups, services, interfaces, clusters
     - None -- just rules with IPs/ports
   * - Routing
     - ``ip route`` generation, ECMP
     - No
   * - Rule analysis
     - Shadowing detection, optimization, negation handling
     - None

**When to use UFW instead:** You have a single server with a handful of simple allow/deny rules and want to manage them directly on the command line.

**When to use FirewallFabrik instead:** You manage multiple firewalls, need NAT, clustering, or complex rule sets, or want reusable objects and rule analysis.


vs. firewalld
^^^^^^^^^^^^^^

firewalld is a dynamic firewall daemon that runs directly on the host. It uses a zone-based model and supports instant runtime changes via its D-Bus API.

.. list-table::
   :header-rows: 1
   :widths: 25 37 38

   * - Aspect
     - FirewallFabrik
     - firewalld
   * - Approach
     - Offline compiler
     - Live daemon (D-Bus API)
   * - Abstraction
     - Objects + rules compiled to scripts
     - Zones + services + rich rules
   * - Multi-firewall
     - Yes
     - No -- per-host daemon
   * - NAT
     - Full NAT matrix
     - Masquerade per zone, basic port forwarding
   * - nftables
     - Native compiler backend
     - Uses nftables as backend (since v0.6)
   * - Object model
     - Hierarchical groups, address tables, service groups
     - Flat zones, predefined services
   * - Rule complexity
     - Arbitrary rule chains, negation, branching
     - Rich rules cover basics, limited nesting
   * - Runtime changes
     - Recompile + redeploy
     - Instant (reload or permanent)

**When to use firewalld instead:** You manage a single host, need instant runtime changes, or rely on tight integration with NetworkManager and systemd.

**When to use FirewallFabrik instead:** You need centralized management of multiple firewalls, complex NAT configurations, custom chain branching, or rule shadowing analysis across your infrastructure.


vs. pfSense / OPNsense
^^^^^^^^^^^^^^^^^^^^^^^^

pfSense and OPNsense are complete firewall operating systems based on FreeBSD. They run on dedicated hardware or virtual machines and provide a full web-based management interface.

.. list-table::
   :header-rows: 1
   :widths: 25 37 38

   * - Aspect
     - FirewallFabrik
     - pfSense / OPNsense
   * - What it is
     - Policy compiler + desktop GUI
     - Full firewall OS (FreeBSD-based)
   * - Runs on
     - Your workstation (designs rules for remote firewalls)
     - Dedicated hardware or VM (is the firewall itself)
   * - Captive portal
     - No
     - Yes
   * - DHCP/DNS
     - No
     - Built-in (ISC DHCP, Unbound)
   * - Firewall engine
     - Currently generates iptables/nftables; open to additional backends
     - PF (Packet Filter) on FreeBSD
   * - HA
     - Cluster modeling + conntrackd
     - Native CARP + pfsync
   * - IDS/IPS
     - No
     - Suricata/Snort integration
   * - Multi-firewall
     - Yes -- central management from one database
     - No -- each appliance is managed individually
   * - NAT
     - Comprehensive for iptables/nftables
     - Comprehensive for PF
   * - Package ecosystem
     - No
     - Extensive (HAProxy, Squid, ntopng, ...)
   * - Rule analysis
     - Shadowing detection, optimization
     - Basic duplicate detection
   * - Traffic shaping
     - Partial (MARK/CLASSIFY for tc)
     - Full ALTQ/CoDel integration
   * - VPN
     - No
     - OpenVPN, WireGuard, IPsec
   * - Web UI
     - No (desktop Qt6 GUI)
     - Yes -- full web management

**When to use pfSense/OPNsense instead:** You want an all-in-one firewall appliance with built-in VPN, IDS/IPS, DNS, DHCP, and a web UI -- typically for branch offices, small-to-medium businesses, or lab environments.

**When to use FirewallFabrik instead:** You need to design, compile, and deploy firewall rules across multiple firewalls from a central workstation. FirewallFabrik does not replace a firewall appliance -- it replaces the need to manually write and maintain firewall rules. It currently targets iptables and nftables, with the architecture open to additional backends.


Strengths of FirewallFabrik
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **Visual overview across all firewalls** -- see the policies of all your firewalls side by side in one application. This makes it easy to maintain an overview, understand cross-firewall communication flows, and spot gaps or inconsistencies that are invisible when managing firewalls individually.
- **Audit and traceability** -- every rule references named objects (hosts, networks, services) rather than raw IP addresses and port numbers. This provides clear traceability: you can instantly find all rules across all firewalls that reference a specific server or service. During audits, reviewers can understand the intent of each rule without deciphering cryptic iptables syntax.
- **Centralized multi-firewall management** -- design rules for dozens of firewalls from one database. A change to a shared object (for example, updating a server's IP address) is automatically reflected in every rule that references it.
- **Rich object model** -- define hosts, networks, and services once, reuse them across all your firewalls. This eliminates duplication and ensures consistency.
- **Complements Infrastructure as Code** -- FirewallFabrik generates standard shell scripts that integrate naturally into any automation pipeline. Use Ansible, Terraform, CI/CD pipelines, or the built-in SSH installer to deploy the compiled output. FirewallFabrik provides the design and compilation layer; your existing automation handles deployment.
- **Compiler intelligence** -- automatic rule shadowing detection, optimization, and negation handling catch errors at compile time, before they reach your firewalls.
- **Full NAT support** -- SNAT, DNAT, Masquerade, Redirect, Load Balancing, SDNAT, NONAT.
- **Dual-stack IPv4/IPv6** -- separate compilation passes with automatic version filtering.
- **Cluster support** -- model failover groups and state synchronization.
- **Idempotent output** -- the generated shell scripts can be re-applied safely. They flush and rebuild the entire rule set on each run, so the result is always the same regardless of the firewall's previous state.
- **Reproducibility** -- generated shell scripts are deterministic and human-readable. Store the ``.fwf`` source file in version control to maintain a complete history of every policy change.


Limitations of FirewallFabrik
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

- **No live runtime** -- FirewallFabrik is not a daemon. Changes require recompilation and redeployment.
- **No network services** -- it does not provide VPN, DNS, DHCP, or IDS/IPS.
- **No web UI** -- it is a desktop application (Qt6), not a web-based tool.
- **Currently iptables and nftables only** -- additional compiler backends (e.g. PF) could be added in the future, but are not available yet (as of 2026).
- **No traffic monitoring** -- it compiles rules but does not observe or visualize live traffic.


Supported Platforms
-------------------

FirewallFabrik's architecture is platform-agnostic -- the object model, rule engine, and GUI are independent of any specific firewall backend. Additional compiler backends can be added as the need arises. Currently, two backends are available:

- **iptables** -- the mature, battle-tested Netfilter firewall framework with a comprehensive compilation pipeline (55+ rule processors).
- **nftables** -- the modern successor to iptables, default on all major Linux distributions, with native support for sets, maps, and a cleaner rule syntax.

Both backends produce deployment-ready output: shell scripts with individual ``iptables`` commands or ``iptables-restore`` batch format for iptables, and ``nft`` batch files for nftables.


Platforms from Firewall Builder Not Carried Forward
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Firewall Builder, the predecessor of FirewallFabrik, supported compilation to nine firewall platforms. FirewallFabrik currently ships with iptables and nftables backends. The following platforms from Firewall Builder have not been carried forward. If you are migrating from Firewall Builder, this overview explains the current status of each.

**Discontinued platforms:**

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - Platform
     - Target
     - Status
   * - Cisco FWSM
     - Firewall Services Module
     - Discontinued by Cisco. No longer deployed.
   * - Cisco PIX
     - PIX 6.x appliances
     - Hardware end-of-life since ~2008. Fully replaced by Cisco ASA.
   * - ipfilter (ipf)
     - Solaris, FreeBSD
     - Oracle Solaris has virtually no market share left. FreeBSD users have moved to PF.
   * - ipfw
     - FreeBSD, macOS
     - Superseded by PF on FreeBSD. macOS also switched to PF.

**Platforms that are still in use but not yet supported:**

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - Platform
     - Target
     - Notes
   * - Cisco ASA
     - ASA 7.x--8.3
     - Cisco ASA is still widely deployed. However, the Firewall Builder compiler targeted ASA up to version 8.3, which introduced a major NAT syntax overhaul. Modern ASA versions (9.x and later) would require a substantially new compiler. Cisco is also transitioning customers to Firepower Threat Defense (FTD).
   * - Cisco IOS ACL
     - IOS 12.1--12.4 routers
     - Cisco IOS routers remain common (modern versions run IOS-XE 16.x/17.x). No compiler backend has been implemented yet, but the architecture would allow adding one.
   * - Cisco NX-OS ACL
     - Nexus 4.2--6.1
     - Cisco Nexus switches are used in data centers (current NX-OS is 10.x). Same situation as IOS -- not currently supported but architecturally possible.
   * - HP ProCurve ACL
     - ProCurve K.13 switches
     - Rebranded to HPE Aruba. A niche switch ACL platform.
   * - Juniper JunOS
     - JunOS 11.2+
     - Juniper is a major player in enterprise networking. No compiler backend has been implemented yet.
   * - PF
     - OpenBSD, FreeBSD
     - PF is actively developed and powers both pfSense and OPNsense. Among the platforms not yet supported, PF would be the most natural candidate for a future compiler backend.

**Added in FirewallFabrik:**

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - Platform
     - Target
     - Notes
   * - nftables
     - Linux (kernel 3.13+)
     - The successor to iptables and the default firewall framework on all major Linux distributions. Firewall Builder never supported nftables. This is a key advantage of FirewallFabrik for modern Linux environments.

**In summary:** FirewallFabrik currently ships with iptables and nftables compiler backends. Its architecture is open by design -- additional backends can be added as demand arises. The discontinued platforms (PIX, FWSM, ipfw, ipfilter) have no remaining audience. The still-active platforms (Cisco ASA/IOS/NX-OS, JunOS, PF) are candidates for future backends, with PF being the most natural fit. The addition of nftables support -- which Firewall Builder never had -- already makes FirewallFabrik more relevant for modern Linux environments than its predecessor.
