Configlets
==========

.. sectnum::
   :start: 1

.. contents::
   :local:
   :depth: 2


Generated firewall scripts are assembled from fragments called "configlets" (iptables) or Jinja2 templates (nftables). Each configlet or template contains placeholders that the compiler replaces with actual strings and values when it generates a firewall configuration. Normally, you don't need to think about them.

However, if you have the need, you can use your own configlets or templates, or modify the existing ones. This lets you change virtually all aspects of generated configuration files.


Configlets (iptables)
---------------------

Default configlets are bundled with the FirewallFabrik package under ``resources/configlets/``. If you create a ``firewallfabrik/configlets`` directory in your home directory and place files with the same name there, FirewallFabrik will use those configlets instead. You need to retain the structure of subdirectories inside this directory. For example, Linux configlets stored in ``$HOME/firewallfabrik/configlets/linux24`` will override the bundled configlets in ``resources/configlets/linux24``.

Configlets provide the commands the built-in policy installer needs to install the policy on the firewall. Two configlets are used for Unix-based firewalls: ``installer_commands_reg_user`` and ``installer_commands_root``. You can change the behavior of the installer by creating a copy of the configlet file in ``$HOME/firewallfabrik/configlets`` and modifying it.


Jinja2 Templates (nftables)
----------------------------

The nftables compiler uses Jinja2 templates instead of configlets. The default templates are bundled under ``resources/templates/nftables/``. The same override mechanism applies: place custom templates in ``$HOME/firewallfabrik/templates/nftables/`` and they will take precedence over the bundled ones.

For example, to customize the nftables shell script wrapper, copy ``resources/templates/nftables/script.sh.j2`` to ``$HOME/firewallfabrik/templates/nftables/script.sh.j2`` and modify it. Jinja2 templates use ``{{ variable }}`` for variable substitution and ``{% if condition %}...{% endif %}`` for conditional blocks.


Configlet Example (iptables)
----------------------------

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

First, we copy the bundled ``resources/configlets/linux24/automatic_rules`` to ``$HOME/firewallfabrik/configlets/linux24/automatic_rules``.

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
