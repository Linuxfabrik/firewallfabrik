Appendix
========

.. sectnum::
   :start: 16

.. contents::
   :local:
   :depth: 2


This chapter provides additional information that may be useful to FirewallFabrik users.


iptables ipset Module
---------------------

FirewallFabrik uses ipset for run-time address tables. The ``ipset`` package must be installed on the firewall machine if you use Address Table objects in run-time mode.

On most modern Linux distributions, ipset is available as a standard package:

.. code-block:: bash

   # Debian/Ubuntu
   apt install ipset

   # Fedora/RHEL
   dnf install ipset

To verify that ipset is working:

.. code-block:: bash

   ipset --version
   ipset -N test hash:ip
   ipset --list
   ipset -X test

If ``ipset --version`` reports an error about missing kernel modules, ensure the ``ip_set`` kernel module is loaded:

.. code-block:: bash

   modprobe ip_set


nftables Sets
-------------

When using nftables as the firewall platform, FirewallFabrik uses native nftables sets instead of ipset. No additional packages are needed beyond the standard ``nftables`` package:

.. code-block:: bash

   # Debian/Ubuntu
   apt install nftables

   # Fedora/RHEL
   dnf install nftables
