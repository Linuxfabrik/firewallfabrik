Manage your Firewall Remotely
=============================

.. sectnum::
   :start: 1

.. contents::
   :local:
   :depth: 2


This chapter explains how to set up a firewall on a small dedicated machine and use a separate workstation to manage it.

The best way to utilize the flexibility of Firewall Builder and to minimize the risk to your network is to run Firewall Builder on a dedicated management workstation. This workstation will have the near-full installation of Linux or FreeBSD, complete with X11 and Gnome or KDE. Alternatively, it can be a Mac or Windows PC.

The reason we do not recommend running X11 and GUI environment on the firewall is actually rather simple. It is well known that complex programs are more prone to errors than simple and short ones. X11 and GUI environments are *very* complex programs, rivaling or exceeding the Linux kernel in size. Granted, you may be safe if you run these on the firewall provided you install all the latest patches and keep your software up-to-date. This, however, means a lot of effort and time spent on maintaining software that is not essential to the operation of the firewall and is being used only once in a while. You may add protection using firewall rules to block all access to the firewall itself from outside (a very good idea regardless whether you run X11 on it), but then you need to carefully watch your policy to make sure you don't drop these rules accidentally. The rules may get more complex if you ever need to manage your firewall remotely, making verification difficult. All this adds up to the risk factor, so it is just a lot simpler to not have X11 and GUI on the firewall at all.

In other words, run X11 and GUI environment on the firewall machine only when you have a definite reason to do so, and keep an open eye on it.

We will look at configuring the dedicated firewall machine and then at configuring the management workstation.


Dedicated Firewall machine
--------------------------

The choice of the hardware for the firewall depends on how much bandwidth is needed by the network it protects. Our experience indicates that an old Pentium machine is sufficient for a group of 2-5 people doing regular web surfing, sending and receiving email and doing some other not-very-demanding tasks. Small firewall appliances made by Linksys or DLink demonstrate good performance as well. These appliances do not allow ssh access by default, so fwbuilder won't be able to upload generated firewall configuration, however their firmware can be replaced with DD-WRT or OpenWRT which enabled ssh and many other powerful features. Firewall Builder 4.0 comes with direct support for OpenWRT and can generate a drop-in replacement for its standard firewall configuration (just choose host OS "OpenWRT" in the firewall object).

We have ran firewalls like that at various times using Linux/iptables, FreeBSD/ipfilter and OpenBSD/pf combinations and can't say that any particular platform has better performance. They all just work. A firewall like one of these won't slow down file transfer on a DSL or a cable network, easily supporting download speeds of 1.5 - 2 Mbit/sec. Since hardware like this is very obsolete and can be had for almost nothing, we never saw the need to investigate which OS and firewall performs better on a slower CPU. People have had good results using old notebooks as their firewalls, too. The advantage of the notebook is that is has a monitor which makes troubleshooting easier in case you make a mistake in the policy rules and block your own access to the firewall over the network.

For a larger installation (more people or long policy) a faster CPU is needed.

The OS installed on the firewall machine should be minimal. Basically, all you need is the kernel, basic tools usually found in /bin, and ssh. This is true regardless of what OS you choose, so just follow installation instructions appropriate for your OS. Do not install development tools, X11, editors, graphics software and so on and you'll be fine. Make sure you get ssh, though, and in some cases you may need Perl.

Once you install the firewall machine, check if the ssh daemon is running. It usually is, but some OS have different installation options and if you choose "workstation" install, they may not start ssh daemon automatically. Use **ps -ax | grep sshd** to check if the daemon is running, and if it is not, activate it.


Using Diskless Firewall Configuration
--------------------------------------

Several projects came up with a decent distributions intended for a small diskless router/firewall. We have experience with *floppyfw* and *Devil Linux*, consequently Firewall Builder has policy install scripts for these. The advantage of using either one of these is that you won't have to install OS and software on the firewall machine; you just pop in a floppy or a CD-ROM and boot from it. This is as close as it comes to the firewall appliance, yet you get a modern Linux kernel and iptables with both. The whole OS is stored on the write-protected media and can be easily replaced or upgraded simply by changing the disk. Floppy FW comes on a single floppy. (These guys managed to pack a kernel, a busybox application and bunch of other programs on a single compressed ram disk.) You don't get ssh with floppyfw though. The firewall configuration is located in a text file that can be edited off-line and then written to the floppy. Firewall Builder's install script also writes the firewall policy to this floppy when you call main menu item Rules/Install. Once configuration is written to the floppy, you insert it in the firewall and reboot. That's it.

Devil Linux comes on a CD-ROM and obviously has lot more stuff on it. They also keep configuration on a floppy disk. Firewall Builder's install script writes firewall policy to this floppy, which you then need to insert in the firewall. See detailed documentation on using *Devil Linux* on their web site.


The Management Workstation
--------------------------

The management workstation runs fwbuilder, so it needs X11 and all other libraries fwbuilder depends upon. Follow Installation instructions in :doc:`02 - Installing Firewall Builder` to install fwbuilder on the machine. Start fwbuilder by typing ``fwbuilder`` at a shell prompt to test it.

Once you get the Firewall Builder GUI up and running on the management workstation, you need to build a firewall policy and, eventually, compile it and install on the firewall. Other sections of this Guide describe all steps of this process. Configuration of the built-in policy installer and different ways to use it to install and activate generated policy on the dedicated firewall can be found in :doc:`10 - Compiling and Installing a Policy`.
