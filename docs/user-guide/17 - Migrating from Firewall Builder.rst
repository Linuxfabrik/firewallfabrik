Migrating from Firewall Builder
================================

.. sectnum::
   :start: 17

.. contents::
   :local:
   :depth: 2


Overview
--------

FirewallFabrik is a modernized port of `Firewall Builder <http://sourceforge.net/projects/fwbuilder>`_ (fwbuilder). If you already have Firewall Builder ``.fwb`` files, you can import them directly into FirewallFabrik and continue working with your existing firewall configurations.

This chapter explains the import process, what to expect, and where FirewallFabrik differs from Firewall Builder.


Importing a .fwb File
---------------------

1. Open FirewallFabrik and select **File > Open** (or press ``Ctrl+O``).
2. In the file dialog, select **Firewall Builder files (\*.fwb)** from the file type filter and choose your ``.fwb`` file.
3. FirewallFabrik parses the XML, converts all objects and rule sets, and loads them into the editor.
4. You can now work with your firewalls, objects, and policies exactly as before.

.. note::

   When you save, the file is always written in the FirewallFabrik YAML format (``.fwf``). The original ``.fwb`` file is not modified.

   If a ``.fwf`` file with the same base name already exists, FirewallFabrik will warn you before overwriting it.


Post-Import Checklist
---------------------

After importing a ``.fwb`` file, verify the following:

**Compiler paths**
   Firewall Builder stored paths to its own compilers (``fwb_ipt``, ``fwb_nft``) in each firewall object. FirewallFabrik detects these legacy paths and offers to clear them so that the built-in compiler is used instead. Accept this dialog unless you have a specific reason not to.

**Platform settings**
   Review each firewall's platform and host OS settings (right-click the firewall > Edit). FirewallFabrik provides sensible defaults for all options via its YAML-based defaults system, but you should verify that the imported values match your environment.

**Compile and compare**
   Compile each firewall and compare the generated ``.fw`` script to the output from Firewall Builder. The scripts should be functionally equivalent, though minor formatting differences are expected.

**Save as .fwf**
   Once you are satisfied, save the file (``Ctrl+S``). This creates the ``.fwf`` file that you will use going forward.


What Gets Imported
------------------

FirewallFabrik imports all objects, rule sets, and settings from a ``.fwb`` file:

* Firewalls, hosts, interfaces, and addresses
* Policy, NAT, and routing rule sets with all rule elements
* Object groups, service groups, and dynamic groups
* Address tables, DNS names, and address ranges
* Time intervals and custom services
* Clusters and cluster groups
* Libraries and their folder structure
* Object comments and tags
* Platform and host OS settings


What Does Not Get Imported
--------------------------

* **Revision history (RCS)** -- Firewall Builder had optional RCS integration. FirewallFabrik does not support RCS; use Git for version control instead.
* **Deleted Objects library** -- Firewall Builder soft-deleted objects into a special library. FirewallFabrik uses permanent deletion. See the :doc:`developer guide <../developer-guide/DesignDecisions>` for the rationale.
* **Unsupported platform settings** -- If your ``.fwb`` file contains firewalls configured for platforms that FirewallFabrik does not support (e.g. Cisco PIX, PF), the objects are imported but cannot be compiled. See `Platform Compatibility`_ below.


Platform Compatibility
----------------------

Firewall Builder supported compilation to nine firewall platforms. FirewallFabrik currently ships with **iptables** and **nftables** backends, plus the new **nftables** backend that Firewall Builder never had.

Discontinued Platforms
~~~~~~~~~~~~~~~~~~~~~~

These platforms have no remaining audience and are not supported:

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

Platforms Not Yet Supported
~~~~~~~~~~~~~~~~~~~~~~~~~~~

These platforms are still in use but no compiler backend has been implemented yet. Firewall objects for these platforms are imported but cannot be compiled.

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - Platform
     - Target
     - Notes
   * - Cisco ASA
     - ASA 7.x--8.3
     - Still widely deployed. The Firewall Builder compiler targeted ASA up to version 8.3. Modern ASA 9.x would require a substantially new compiler. Cisco is transitioning to Firepower Threat Defense (FTD).
   * - Cisco IOS ACL
     - IOS 12.1--12.4 routers
     - Cisco IOS routers remain common (modern versions run IOS-XE 16.x/17.x). Architecturally possible to add.
   * - Cisco NX-OS ACL
     - Nexus 4.2--6.1
     - Cisco Nexus switches are used in data centers (current NX-OS is 10.x). Architecturally possible to add.
   * - HP ProCurve ACL
     - ProCurve K.13 switches
     - Rebranded to HPE Aruba. A niche switch ACL platform.
   * - Juniper JunOS
     - JunOS 11.2+
     - Juniper is a major player in enterprise networking.
   * - PF
     - OpenBSD, FreeBSD
     - Actively developed, powers pfSense and OPNsense. Among the unsupported platforms, PF would be the most natural candidate for a future backend.

Added in FirewallFabrik
~~~~~~~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 20 25 55

   * - Platform
     - Target
     - Notes
   * - nftables
     - Linux (kernel 3.13+)
     - The successor to iptables and the default firewall framework on all major Linux distributions. Firewall Builder never supported nftables.


Key Differences from Firewall Builder
--------------------------------------

File format
   FirewallFabrik uses YAML (``.fwf``) instead of XML (``.fwb``). The YAML format is human-readable, diff-friendly, and works well with Git.

No RCS
   Version control is handled externally (Git recommended) instead of built-in RCS.

No deleted objects library
   Objects are permanently deleted. Use Git to recover accidentally deleted objects.

No SNMP discovery
   The SNMP-based network discovery feature has been removed. Create objects manually or import from a ``.fwb`` file.

No policy import
   Importing firewall configurations from running devices (e.g. parsing ``iptables-save`` output) is not available.

ULOG removed
   The ULOG logging target has been removed from modern Linux kernels (replaced by NFLOG). If your ``.fwb`` file had ``use_ULOG`` enabled, it is silently migrated to the standard LOG target during import. NFLOG support is planned but not yet implemented in the compiler — LOG and NFLOG are shown as radio buttons in the platform settings, with NFLOG currently disabled.

Legacy logging and bridge options
   Several advanced iptables logging options (log TCP sequence numbers, log TCP/IP options, numeric syslog levels, kernel timezone, unconditional rule logging) and bridge interface configuration are legacy features with no remaining audience and are not supported. The corresponding checkboxes in the platform settings dialogs are disabled. If your ``.fwb`` file had any of these options enabled, you will see a compiler warning.

Desktop integration
   FirewallFabrik registers ``.fwf`` and ``.fwb`` MIME types for file manager integration. See :doc:`02 - Installing FirewallFabrik` for setup instructions.

nftables support
   FirewallFabrik adds native nftables compilation, which Firewall Builder never had.

Parallel compilation
   FirewallFabrik compiles multiple firewalls concurrently (up to the number of CPU cores). Firewall Builder compiled firewalls one at a time. The CLI compilers (``fwf-ipt``, ``fwf-nft``) also accept multiple firewall names and an ``--all`` flag, loading the database only once.

DiffServ default
   Firewall Builder defaulted to "Use TOS" in the IPService dialog when neither TOS nor DSCP was set. FirewallFabrik defaults to neither selected — the DSCP/TOS code field is disabled until the user explicitly chooses DSCP or TOS, making it clear that the setting has no effect without a code value. When a selection is needed, DSCP is recommended as the modern standard.

IPv4 packet forwarding default
   Firewall Builder defaulted to enabling IPv4 packet forwarding. FirewallFabrik defaults to "No change" (does not modify the kernel setting).
