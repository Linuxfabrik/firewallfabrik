Troubleshooting
===============

.. sectnum::
   :start: 1

.. contents::
   :local:
   :depth: 2


This chapter provides tips for troubleshooting problems with the program.

Build Issues
------------

autogen.sh Complains "libfwbuilder not installed"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When compiling from source, ``autogen.sh`` complains "libfwbuilder not installed"

As of version 0.9.6 the code has been split into three major parts: API, GUI and policy compilers. You need to download, compile and install API for the rest to compile. The API comes in a separate source archive called ``libfwbuilder-0.10.0.tar.gz``. Compile and install it as usual, using ``./autogen.sh; make; make install`` procedure.

"Failed dependencies: ..." when installing RPM
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Trying to install Firewall Builder RPM but I get a bunch of errors "Failed dependencies: ...". What do I need to do?

You need to install prerequisite libraries. See the list of RPMs in the appendix.

.. note::

   Do not use options ``--force`` or ``--nodeps`` when you install fwbuilder RPMs. If rpm complains about unsatisfied dependencies, this means your system is missing some libraries, or the wrong versions are installed. Forcing the package install won't fix that; most likely it will fail in one way or another.

Program Startup Issues
----------------------

"fwbuilder: cannot connect to X server localhost:0.0"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Firewall Builder binary does not start. Error "fwbuilder: cannot connect to X server localhost:0.0" or similar.

The Firewall Builder GUI is an X application, that is, it needs X server to display it on the screen. The program determines how to connect to the X server using environment variable ``DISPLAY``; you probably do not have this environment variable if you get an error like that. The simplest way to avoid this problem is to start fwbuilder from the shell window in Gnome or KDE environment.

It may also be that the environment variable ``DISPLAY`` is set, but the program fwbuilder cannot connect to the X server. In this situation you won't be able to run any application using X, check if that's the case by trying to start ``xclock``. This may be happening because of many different reasons, such as X server is not running, X authentication failure, or ``DISPLAY`` variable reassigned its value by the shell login script or many others. This problem falls outside the scope of this document, please search on the Internet for the answer. Here are few URLs to make troubleshooting easier:

- http://www.openssh.org/faq.html
- http://en.tldp.org/HOWTO/XDMCP-HOWTO/ssh.html
- http://en.tldp.org/LDP/intro-linux/html/sect_10_03.html

"fwbuilder: error while loading shared libraries: libfwbuilder.so.0"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

fwbuilder binary does not start. Error "fwbuilder: error while loading shared libraries: libfwbuilder.so.0: cannot load shared object file: no such file or directory."

The GUI binary (fwbuilder) cannot find API library ``libfwbuilder``. If you are using our binary packages, then make sure you download and install package called ``libfwbuilder``. If you compiled from sources, then perhaps you installed libfwbuilder with default prefix ``/usr/local/``, therefore library went to ``/usr/local/lib``. Dynamic linker ``ldd`` cannot find it there.

You have the following options:

- Create environment variable ``LD_LIBRARY_PATH`` with value ``/usr/local/lib`` and run fwbuilder from this environment.
- Add ``/usr/local/lib`` to the file ``/etc/ld.so.conf`` and run ``ldconfig`` so it will rescan dynamic libraries and add them to its cache.
- Recompile libfwbuilder and fwbuilder with prefix ``/usr/``, this will install ``libfwbuilder.so.0`` in ``/usr/lib``. ``ldd`` will find it there without any changes to environment variables or ``/etc/ld.so.conf`` file. To change prefix you need to run ``autogen.sh`` with command line parameter ``--prefix=/usr``. Do this both for libfwbuilder and fwbuilder.

"fwbuilder: error while loading shared libraries: cannot restore segment prot after reloc: Permission denied"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

fwbuilder binary does not start. Error "fwbuilder: error while loading shared libraries: /usr/local/lib/libfwbuilder.so.8: cannot restore segment prot after reloc: Permission denied"

The problem is caused by SELinux security settings, to work around it try the following command:

.. code-block:: bash

   chcon -t texrel_shlib_t /usr/lib/libfwbuilder.so*

Firewall Compiler and Other Runtime Issues
------------------------------------------

Firewall Builder Crashes
~~~~~~~~~~~~~~~~~~~~~~~~

Firewall Builder or Policy Compiler Crashes

Please file a bug on Sourceforge. Provide information we might need to fix the problem. See the `Firewall Builder Contact <http://www.fwbuilder.org/contact.html>`_ page for links to bug tracking and instructions for filing bugs.

Older Data File Cannot Be Loaded in Firewall Builder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Data file created in the older version of fwbuilder cannot be loaded in the latest one.

Sometimes this happens when you skip several versions trying to upgrade the program. There used to be a bug in the upgrade procedure somewhere around version 1.0.4 which broke automatic upgrades from versions before 1.0.4 to versions after that. If this happens to you, upgrade your data file using script ``fwb-upgrade.sh`` that you can find in ``Contrib/Scripts`` area on our SourceForge site.

"I/O Error" While Compiling Policy. No Other Error.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"I/O Error" while compiling policy. There is no other indication of error though.

Did you install the package with the corresponding compiler? Our pre-built compilers come in separate RPMs named like this: ``fwbuilder-ipt-2.0.2-1rh9.i386.rpm``

Check if compiler dumped core. If you can't find it, you may try to run compiler manually, providing the following command-line parameters:

.. code-block:: bash

   fwb_ipt -f path_to_objects.xml firewall_object_name

All policy compilers have the same command line format.

ios_base::failbit set on Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Policy compiler stops with an error ``ios_base::failbit set`` on Windows.

It looks something like this:

.. code-block:: text

   fwb_ipfw -f C:/Documents and Settings/User/data.fwb -d C:/Documents
   and Settings/User -r C:\FWBuilder\resources fw

    Compiling policy for fw ...
     Detecting rule shadowing
    Begin processing
    Policy compiled successfully
   ios_base::failbit set

First of all, check available free disk space. Also check if the output file (``fw.fw``) is opened in another program while compiler is running. That is, if you looked at it after the previous compiler run and opened it in Notepad, it becomes locked and compiler won't be able to overwrite it with the new copy until you close Notepad.

"Cannot create virtual address NN.NN.NN.NN"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Policy compiler stops processing rules with error message "Cannot create virtual address NN.NN.NN.NN"

This happens when you are using an option "Create virtual addresses for NAT rules". The problem is that policy compiler needs to be able to determine interface of the firewall to assign virtual address to. In order to do that it scans all interfaces trying to find subnet requested NAT address is on. Sometimes the firewall's interface has an address which belongs to a different network than the NAT address specified in the rule; in this case, the compiler cannot identify an interface and aborts.

The NAT rule still can be built without ``-i`` or ``-o`` option, but automatic assignment of virtual address is impossible. You need to turn off option "Create virtual addresses for NAT rules" in the tab "Firewall" of firewall dialog and configure this address manually.

Troubleshooting Installing Policy on the Firewall
--------------------------------------------------

Plink.exe Fails with Error "Looking up host '' Connecting to 0.0.0.0 port 22"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This only happens when Firewall Builder GUI runs on Windows and uses ``pscp.exe`` and ``plink.exe`` to transfer generated firewall script and activate it on the firewall machine. The utilities ``pscp.exe`` and ``plink.exe`` are part of the `PuTTY package by Simon Tatham <http://www.chiark.greenend.org.uk/~sgtatham/putty/>`_.

The Firewall Builder GUI launches the ``plink.exe`` utility to log in to the firewall machine and activate firewall script there. It composes ``plink.exe`` command line using ip address of the firewall and adds command line option ``-ssh`` to force ``plink.exe`` to use ssh protocol. ``Plink.exe`` and GUI ssh client ``putty.exe`` share the same configuration stored in windows registry and if default settings configured in ``putty.exe`` set default protocol to "Serial" as shown in the screenshot below, ``plink.exe`` seems to ignore command line option ``-ssh`` and fails with an error "Looking up host '' Connecting to 0.0.0.0 port 22". Just set the default protocol to "ssh" using the putty configuration dialog.

.. figure:: img/troubleshoot-putty-configuration.png
   :alt: PuTTY Configuration showing default protocol setting

   Figure 15.1: PuTTY Configuration

Running the Firewall Script
----------------------------

Determining Which Rule Caused an Error
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I get an error when I run the generated script. How can I figure out which rule causes this error?

You can turn debugging on (look for a checkbox in the tab "Firewall" in firewall dialog). This simply generates firewall script with shell option ``-x`` so it will print all commands while executing. This way you can see which command causes the error and trace it back to the policy rule.

"ip: command not found"
~~~~~~~~~~~~~~~~~~~~~~~

(Linux / iptables only) I've generated script for iptables firewall using Firewall Builder, but when I run it I get an error "ip: command not found". What is this command for and what package should I install?

This tool is part of the package ``iproute``; we use it to manage virtual IP addresses needed for some NAT rules.

"iptables: can't initialize iptables table 'drop'"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I get the following error when I run generated script for iptables firewall: "iptables v1.2.8: can't initialize iptables table 'drop': Table does not exist (do you need to insmod?) Perhaps iptables or your kernel needs to be upgraded."

You get this error because you used the option "Log all dropped packets" (there is a checkbox in the "Firewall" tab). This option requires the "dropped" patch from patch-o-matic. You either need to turn this option off, or apply the corresponding patch and recompile both kernel modules and command-line utilities for iptables.

"Interface eth0 does not exist"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You are trying to execute an iptables script generated by Firewall Builder but get an error message "Interface eth0 does not exist" or similar.

There are several conditions that may cause this error.

The script generated by Firewall Builder uses the tool ``/sbin/ip`` to verify configuration of the firewall interfaces and make sure that interfaces of the real firewall machine correspond to the interface objects created in the GUI. You may get this error if the tool ``/sbin/ip`` is not installed on your system. All modern Linux distributions come with the package ``iproute2`` which includes ``/sbin/ip``; check if ``iproute2`` is installed and ``/sbin/ip`` exists.

Another case when you may encounter this error is when firewall script is executed prematurely during the boot sequence and interface really does not exist at that time. For example, interface ``ppp0`` is created only when the system is configured for PPP and the daemon ``pppd`` is running. If the firewall script is activated before the daemon started during the boot sequence, interface ``ppp0`` is not there yet, which leads to this error. Make sure you start firewall script after all interfaces have been initialized.

"Interface eth0:1 does not exist"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

My firewall has virtual interface ``eth0:1``. In fwbuilder I added the interface, however, when I want to apply the new rules I get the error "Interface eth0:1 does not exist".

``eth0:1`` is not a real interface on Linux, it is just a label for a second IP address of the interface ``eth0``. One way to solve this is not to create it in the OS (remove file ``/etc/sysconfig/network-scripts/ifcfg-eth0:1`` and restart networking), but rather add its IP address in the Firewall Builder GUI as a second address to interface ``eth0``.

In any case you should not add interface ``eth0:1`` in fwbuilder because it really does not exist. Iptables will not recognize this interface either, so even if Firewall Builder did allow you to use it, you would get an error from iptables. You see ``eth0:1`` in the output of ``ifconfig`` only because ``ifconfig`` has been modified on Linux to show virtual IP addresses as pseudo-interfaces. The command ``ip addr show`` will reveal that ``eth0:1`` is really a label on the second IP address of ``eth0``.

Script Fails to Load Module nf_conntrack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Generated script fails to load module ``nf_conntrack`` when it is executed on the firewall.

This problem is specific to iptables. The answer below has been written in September 2006, most likely the situation and relevant recommendations will change as the module ``nf_conntrack`` matures and gets wider deployment.

Here is an example of an error message:

.. code-block:: text

   FATAL: Error inserting nf_conntrack_ipv4
   (/lib/modules/2.6.13-15.11-default/kernel/net/ipv4/netfilter/nf_conntrack_ipv4.ko):
   Device or resource busy

Here is the link to the `nf_conntrack page in patch-o-matic catalog <http://www.netfilter.org/projects/patch-o-matic/pom-extra.html#pom-extra-nf_conntrack>`_. Here is the link to the `discussion on netfilter-devel mailing list <http://lists.netfilter.org/pipermail/netfilter-devel/2006-July/024879.html>`_.

It appears you can load either ``ip_conntrack`` or ``nf_conntrack`` but not both at the same time since ``nf_conntrack`` is a replacement for ``ip_conntrack``. As of this writing, ``nf_conntrack`` does not support NAT just yet and is marked as having status "TESTING" on the patch-o-matic catalog page.

This actually represents a problem for fwbuilder. I would like to avoid having to write extensive GUI to let user choose which modules they want to load. One of the reasons is that the GUI may be working on one machine, while generated firewall script will be executed on another. In this situation the GUI cannot determine which modules are available on the firewall. Currently generated script simply tries to load all modules but it aborts if it detects an error in the command that does it (``modprobe``).

Until a better solution is found, you would probably need to remove the module that conflicts with others or disable the feature that makes the generated script load modules and write your own script to load modules you need. You can for example add commands to load modules explicitly to the "prolog" section of the generated script.

RCS Troubleshooting
-------------------

Error Adding File to RCS
~~~~~~~~~~~~~~~~~~~~~~~~~

Error adding file to RCS: Fatal error during initial RCS checkin of file

You will get this error if you do not have RCS set up on your system. To resolve it, install and configure RCS on the workstation running Firewall Builder.

"Error checking file out: co: RCS file is in use"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I cannot open my data file, I get error "Error checking file out: co: RCS file c:/fwbuilder/RCS/file.fwb is in use"

A catastrophe (e.g. a system crash) can cause RCS to leave behind a semaphore file that causes later invocations of RCS to claim that the RCS file is in use. To fix this, remove the semaphore file. A semaphore file name typically begins with ``,`` or ends with ``_``.

If not that, then it could be another manifestation of bug #1908351.

See if there is a file with the name starting and ending with a comma in the RCS directory (like ``,file.fwb,``). The file should have length of zero bytes. This file is a lock file, it is created and deleted by RCS tools. Bug 1908351 caused this lock file to be left behind. When that happens, ``ci`` won't check file in because it thinks another copy of ``ci`` is already running. Likewise, ``co`` won't check the file out for the same reason. If such file exists (zero bytes in length and name starting or ending with a comma), just delete it and try to check your data file out again.

"Error checking file out:"
~~~~~~~~~~~~~~~~~~~~~~~~~~~

I cannot open my data file, I get error "Error checking file out:"

Such non-descriptive error message is usually caused by hard unrecoverable errors experienced by RCS tools. Unfortunately these tools not always report errors in the best way possible and when this happens, Firewall Builder GUI cannot provide any better diagnostics than it gets from the tool. Such poor diagnostics of errors happens more frequently on Windows than on other platforms.

Here are few things to check and try:

- First of all, check file permissions. The data file (``.fwb``) should be read-only. RCS repository file (``.fwb,v``) should also be read-only. Repository file may be located in subdirectory ``RCS`` but that depends on the OS. It may be located in the same directory with corresponding data file (``.fwb``) as well.

- Try to check the file out manually to see if you can get better diagnostics:

  If you use Windows, start MS DOS window and in it navigate to the folder where you keep your files, then execute the following command:

  .. code-block:: text

     c:\FWBuilder\co.exe -l filename.fwb

  If it checks the file out successfully, it just prints revision number and "done". Otherwise it will print some error.

  After you do that, you need to check the file in to RCS again. Do it like this:

  .. code-block:: text

     c:\FWBuilder\ci.exe -u filename.fwb

  Since the file hasn't changed, it should just check it in without asking you for the RCS log record. If you can successfully check it out and then check it in again from the command line, then the GUI should work too.

  On Linux, \*BSD and Mac OS X the process is exactly the same, except for the path to the checkout and checkin commands:

  To check the file out use:

  .. code-block:: bash

     co -l filename.fwb

  To check the file in use:

  .. code-block:: bash

     ci -u filename.fwb

Issues After New Policy Activation
-----------------------------------

Cannot Access Only Some Web Sites
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Can access most web sites through the firewall just fine, except for a few.

The browser would state "waiting for www.somesite.com" for a while and then time out when you connect to one of these sites.

This might be caused by a MTU problem if you are on a DSL connection using PPPoE. Here are a couple of useful pages that describe the problem in details:

- http://www.dslreports.com/tweaks/MTU
- http://www.internetweekly.org/llarrow/mtumss.html

If your firewall runs iptables you can use option "Clamp MSS to MTU" in the firewall settings dialog to work around it.

For the PF firewalls similar option is called "Enforce maximum MSS" and is located in the "Scrub rule options" tab of firewall settings dialog. It allows for setting MSS value of TCP sessions opened through the firewall; try values between 1460 or 1464 (1464 is the maximum MSS value that can be used on PPPoE connections without fragmentation).

There is no way to change MSS value on the ipf, ipfw and pix firewalls. If your firewall is one of these, you may need to change MTU on your workstation. See links above for recommendations on how to do it.

Firewall Becomes Very Slow with New Policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You compiled and started firewall policy script and then noticed that seemingly every operation on the firewall takes a lot longer than before. For example, it takes forever to log into it using telnet or ssh, different services take a few minutes to start or won't start at all.

Most likely the firewall needs to be able to do DNS lookups but can't. Look in ``/etc/resolv.conf`` for the address of the name server it is using and make sure you have a rule in the policy to permit connections to it. Use firewall object in "Source", the name server object in "Destination" and a standard service object group "DNS" in the Service field.

If your firewall runs caching name server and file ``/etc/resolv.conf`` lists ``127.0.0.1`` as a name server address, then you need to permit firewall to talk to itself. This rule should have the firewall object in Source, Destination should be set to "any" and the same standard service object group "DNS" should be used in the Service element. Now not only firewall can query the name server process running on it, but the process in turn can send queries to other name servers on the Internet and receive answers.

Here is the rule that should be added to the loopback interface:

.. figure:: img/troubleshoot-dns-on-loopback.png
   :alt: DNS rule on loopback interface -- Source: fw, Destination: fw, Service: DNS, Interface: lo, Direction: Both, Action: Accept

   Figure 15.2: DNS on loopback

Here is the rule that permits name server process to communicate with name servers on the Internet:

.. figure:: img/troubleshoot-dns-to-name-servers.png
   :alt: DNS rule to name servers -- Source: fw, Destination: Any, Service: DNS, Interface: All, Direction: Both, Action: Accept

   Figure 15.3: DNS to name servers

Depending on your policy design, you may want to permit all services rather than just DNS on the loopback interface because there are many other processes that need to be able to communicate with the same host, such as X11, RPC and others. The dedicated firewall machine should not run anything unnecessary, so there you may experiment with limiting the number of services in the rule on the loopback interface. On the other hand, if you use fwbuilder to protect a server that runs many different services, permitting any service on the loopback may be a simpler solution.

The next rule permits processes running on the firewall to communicate with other processes running on the same machine on all protocols:

.. figure:: img/troubleshoot-any-to-any-firewall.png
   :alt: Any to any rule on firewall -- Source: fw, Destination: fw, Service: Any, Interface: lo, Direction: Both, Action: Accept

   Figure 15.4: Any to any on firewall

X Won't Start on a Server Protected by the Firewall
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You've built a firewall script to protect a server, but after you ran the script, X (KDE, Gnome) won't start anymore.

The reason for this is the same as in the DNS problem -- you need a rule to permit processes to communicate with other processes running on the same machine. This can easily be achieved with the following rule added to the loopback interface:

.. figure:: img/troubleshoot-any-to-any-firewall-loopback.png
   :alt: Any to any rule on firewall loopback -- Source: fw, Destination: fw, Service: Any, Interface: lo, Direction: Both, Action: Accept

   Figure 15.5: Any to any on firewall (loopback)

Cannot Access Internet from Behind Firewall
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I compiled and activated firewall policy, but workstations behind the firewall still cannot access the Internet.

Here are a few troubleshooting steps:

- Make sure you compiled, then installed and activated firewall policy. Were there any errors during compile and activation?
- Check if ip forwarding is turned on (pull down menu in the "Network" tab of the firewall object dialog).
- Try to ping hosts on the Internet by their IP address, not their name. This helps isolate DNS problems. If you can ping by address but can't ping by name, then you need to add policy rules to permit DNS queries.
- Look in firewall's log for records indicating that it drops packets. Error in the policy design can cause it to block connections that you really want to go through.
- Use option "Log everything" to make all rules generate log entries, this sometimes helps pinpoint a rule that drops packets.

Things to check in the policy:

- Check if you have a NAT rule if your protected network is using "private" IP addresses.
- If the NAT rule is there, then you may need to add a policy rule to actually permit connections from the protected network.
- In case when NAT is not used, check if the routing is configured properly. If your firewall separates subnets A and B, and you are trying to connect from the host on subnet A to the host on subnet B, then both hosts should have routing to the opposite network. Host on the net A needs a route for the net B, pointing at the firewall. Similarly, host on the net B needs a route for the net A, also pointing at the firewall. If one (or both) host has a default route pointing at the firewall, then it won't need a special route for another network.

Installing Updated Firewall Policy Seems to Make No Difference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

I compiled and activated firewall policy, but my tests seem to show no difference. If I add a rule to block some protocol, it remains permitted for some reason.

Here are a few troubleshooting steps:

First of all, make sure you compile the right firewall object and install on the right firewall machine, the same one you use for testing. It is all too easy to mix them up if you have several firewalls. Another case when this happens often is when you work on the firewall replacement and have both old and new firewall machines running simultaneously. You may be pushing updated policy to the new machine, while traffic is still routed through the old one.

If you test by adding a rule to deny some protocol and then trying to connect with this protocol, but it remains permitted, check that you do not have any rules that permit it above the one you've added for testing. You can use "Find" function (see :doc:`05 - Working with Objects`) in Firewall Builder GUI to find all uses of any service object. Keep in mind that there could be two objects with different names but the same port and protocol configuration. You can search for objects by their name, tcp/udp port number, ip address etc.

If you use ssh access to test rules by adding a rule that denies ssh access to the firewall, keep in mind that automatic rule may override it. The automatic rule is added using checkbox "Always permit ssh access from the management workstation" in the firewall settings dialog. See :doc:`10 - Compiling and Installing a Policy`.

Pay attention to the output that appears in the progress window of the policy installer when you install and activate updated policy. Iptables script generated by fwbuilder always prints the following information when it is activated (here is an example):

.. code-block:: text

   Activating firewall script generated Mon Aug 09 17:22:11 2010 by vadim
   Running prolog script
   Verifying interfaces: eth0 eth1 lo
   Rule 0 (NAT)
   Rule 0 (eth0)
   Rule 1 (lo)
   Rule 2 (global)
   Rule 3 (global)
   Rule 4 (global)
   Rule 5 (global)
   Rule 6 (global)
   Rule 7 (global)
   Rule 8 (global)
   Rule 9 (global)
   Running epilog script

Do you see the "Activating firewall script ..." line in the progress output of the installer? If not, you might be running different script on the firewall. Compare the date and time reported by the script, could it be too old?

.. note::

   Output shown above appears in the progress output of the installer when you run it with both "Quiet" and "Verbose" options turned off. Running it with "quiet" turned on suppresses these lines and running it in verbose mode produces a lot more output.

Another reason updated policy may not be activated is if you tried an external activation script previously but perhaps forgot about it. In this case the installer will be running this script instead of newly generated firewall script. You can configure alternative command that installer should execute on the firewall in the "Installer" tab of the firewall settings dialog. If this option is set to some script on the firewall machine and this script does not in turn call script generated by fwbuilder, you might be reloading the same firewall policy every time you install. This is just another thing to check.

Routing Rules Issues
--------------------

Compile Fails with Dynamic or Point-to-Point Interfaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you have interfaces with a dynamic address or a point-to-point address and you try to insert a routing rule for the default gateway, compilation might fail, stating "gateway not reachable". Typically this is the case for DSL dial-up links. Solution: leave the gateway field empty. Just specify the interface.
