Configlets
==========

.. sectnum::
   :start: 13

.. contents::
   :local:
   :depth: 3

Generated firewall scripts are assembled from fragments called "configlets." Each configlet is a template. The program replaces configlet macros with actual strings and values when it generates a firewall configuration. Normally, you don't need to think about them.

However, if you have the need, you can use your own configlets or modify the existing ones. Using your own configlets, you can change virtually all aspects of generated configuration files.

Default configlets are stored in ``/usr/share/fwbuilder-4.0.0/configlets`` on Linux, ``C:\FWBuilder40\resources\configlets`` on Windows, and ``fwbuilder400.app/Contents/Resources/configlets`` on a Mac. If you create a ``fwbuilder/configlets`` directory in your home directory and place files with the same name there, Firewall Builder will use those configlets instead. You need to retain the structure of subdirectories inside this directory. For example, Linux configlets stored in ``$HOME/fwbuilder/configlets/linux24`` will override the configlets installed in ``/usr/share/fwbuilder/configlets/linux24``.

Configlets provide the commands the built-in policy installer needs to install the policy on the firewall. Two configlets are used for Unix-based firewalls (Linux, OpenWRT, Sveasoft, IPCOP and its variants, OpenBSD, FreeBSD, MacOSX, Solaris): ``installer_commands_reg_user`` and ``installer_commands_root``. You can change the behavior of the installer without having to touch C++ code: just create a copy of the configlet file in ``$HOME/fwbuilder/configlets`` and modify it.


Configlet Example
-----------------

In this section, we'll show how modifying a configlet lets you tailor your generated configuration file.

First, we'll generate a basic firewall policy using the "fw template 1" template. (See the Firewall Object section in :doc:`05 - Working with Objects` for details.)

Then, we'll tell the firewall to always accept SSH connections from the management server at 192.168.1.100. To do this, we select Firewall Settings from the firewall's object editor panel, then enter the management server IP address in the "Always permit ssh access from the management workstation with this address" field.

.. figure:: img/configlet-firewall-settings-dialog.png
   :alt: Firewall Settings Dialog showing iptables compiler options and SSH access configuration

   Firewall Settings Dialog (iptables).

We then save and compile the firewall. If we look into the generated .fw file, we see the following:

.. code-block:: text

   # --------------- Table 'filter', automatic rules
   # accept established sessions
   $IPTABLES -A INPUT    -m state --state ESTABLISHED,RELATED -j ACCEPT
   $IPTABLES -A OUTPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
   $IPTABLES -A FORWARD  -m state --state ESTABLISHED,RELATED -j ACCEPT
   # backup ssh access
   $IPTABLES -A INPUT  -p tcp -m tcp  -s 192.168.1.100/255.255.255.255 \
       --dport 22  -m state --state NEW,ESTABLISHED -j    ACCEPT
   $IPTABLES -A OUTPUT  -p tcp -m tcp  -d 192.168.1.100/255.255.255.255 \
       --sport 22  -m state --state ESTABLISHED,RELATED -j ACCEPT

Now suppose we want to limit SSH access from the management workstation so that it can only connect to the management interface of the firewall.

First, we copy ``/usr/share/fwbuilder-4.0.0/configlets/linux24/automatic_rules`` to ``$HOME/fwbuilder/configlets/linux24/automatic_rules``.

Then, we open our copy of automatic_rules in a text editor and look for this section of the code:

.. code-block:: text

   {{if mgmt_access}}
   # backup ssh access
   {{$begin_rule}} INPUT  -p tcp -m tcp  -s {{$ssh_management_address}}  --dport 22  \
           -m state --state NEW,ESTABLISHED -j  ACCEPT {{$end_rule}}
   {{$begin_rule}} OUTPUT  -p tcp -m tcp  -d {{$ssh_management_address}}  --sport 22  \
           -m state --state ESTABLISHED,RELATED -j ACCEPT {{$end_rule}}
   {{endif}}

To limit SSH connections to the management interface of the firewall, we modify the configlet as follows:

.. code-block:: text

   {{if mgmt_access}}
   # backup ssh access
   {{$begin_rule}} INPUT -i {{$management_interface}} -p tcp -m tcp \
           -s {{$ssh_management_address}}  --dport 22 \
           -m state --state NEW,ESTABLISHED -j  ACCEPT {{$end_rule}}
   {{$begin_rule}} OUTPUT  -o {{$management_interface}} -p tcp -m tcp \
           -d {{$ssh_management_address}}  --sport 22 \
           -m state --state ESTABLISHED,RELATED -j ACCEPT {{$end_rule}}
   {{endif}}

The variable ``{{$management_interface}}`` is not used by the original configlet, but it is documented in the comment at the top of the configlet file.

Now we can save the configlet and recompile the firewall. Then, we look at the generated .fw file again.

.. code-block:: text

   # --------------- Table 'filter', automatic rules
   # accept established sessions
   $IPTABLES -A INPUT    -m state --state ESTABLISHED,RELATED -j ACCEPT
   $IPTABLES -A OUTPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
   $IPTABLES -A FORWARD  -m state --state ESTABLISHED,RELATED -j ACCEPT
   # backup ssh access
   $IPTABLES -A INPUT -i eth1 -p tcp -m tcp \
           -s 192.168.1.100/255.255.255.255  --dport 22 \
           -m state --state NEW,ESTABLISHED -j  ACCEPT
   $IPTABLES -A OUTPUT  -o eth1 -p tcp -m tcp \
           -d 192.168.1.100/255.255.255.255  --sport 22 \
           -m state --state ESTABLISHED,RELATED -j ACCEPT

As you can see, the rules, instead of being general, now specify eth1.
