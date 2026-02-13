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

If you work for a large distributed organization with many administrators, you can assemble address and service objects that describe your network in a library and save it to a data file, then distribute it for other administrators to use. You can also create your own templates for the firewall objects and rules and use them to quickly create new configurations.

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
