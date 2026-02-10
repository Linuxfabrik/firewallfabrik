Appendix
========

.. sectnum::
   :start: 1

.. contents::
   :local:
   :depth: 2


This chapter provides additional information that may be useful to Firewall Builder users.

iptables modules
----------------

Installing the iptables ipset Module Using xtables-addons
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Instructions for installing the iptables ipset module using xtables-addons.

On Ubuntu, the module ipset and corresponding command-line tools are packaged in either package *ipset* and *ipset-module-source* or as part of an *xtables-addons* bundle. The latter includes many other useful iptables modules and tools besides ipset. You can use just ipset packages if you do not need other modules; otherwise, it probably makes sense to install xtables-addons. These packages are mutually exclusive, that is, if you install ipset and ipset module packages and then later will try to install xtables-addons to get some other module, you are going to have to deinstall ipset packages to avoid conflict. The instructions below illustrate method using *xtables-addons*.

First, you need to obtain the ipset module source. You can do this by running the commands shown below.

.. note::

   You will need to be root or have sudo access to run these commands. Depending on what is already installed on your system you might see slightly different command outputs.

Two packages xtables-addons that we need to install have the following descriptions

.. code-block:: text

   # aptitude search xtables
   p   xtables-addons-common  - Extensions targets and matches for iptables [tools, libs]
   p   xtables-addons-source  - Extensions targets and matches for iptables [modules sources]

We need to install both using the following commands (as root):

.. code-block:: bash

   # aptitude install xtables-addons-common
   # aptitude install xtables-addons-source

Next, you will need to build the iptables modules installed by the package ``xtables-addons-source`` from source. We use the convenient ``module-assistant`` for this. You will see a window pop-up that displays the status of the module being built.

.. code-block:: bash

   # module-assistant build xtables-addons

This command builds binary package with all the modules but does not automatically install it. You need to install it manually. The command prints module file name and path at the end of its run, like this:

.. code-block:: text

   root@lucid:~# module-assistant build xtables-addons
   Extracting the package tarball, /usr/src/xtables-addons.tar.bz2, please wait...
   Done with /usr/src/xtables-addons-modules-2.6.32-22-generic-pae_1.21-1+2.6.32-22.36_i386.deb .

Package name is ``/usr/src/xtables-addons-modules-2.6.32-22-generic-pae_1.21-1+2.6.32-22.36_i386.deb``, we can install it using ``dpkg -i`` command:

.. code-block:: bash

   # dpkg -i \
     /usr/src/xtables-addons-modules-2.6.32-22-generic-pae_1.21-1+2.6.32-22.36_i386.deb

Command line tool ``ipset`` was installed previously as part of the *xtables-addons-common* package.

Your ipset module installation should now be complete. To confirm that the installation was successful try running the following commands.

.. code-block:: text

   fwbuilder@guardian:~$ sudo ipset --version
   ipset v4.1, protocol version 4.
   Kernel module protocol version 4.
   fwbuilder@guardian:~$
   fwbuilder@guardian:~$ sudo ipset -N test iphash
   fwbuilder@guardian:~$
   fwbuilder@guardian:~$ sudo ipset --list
   [sudo] password for fwbuilder:
   Name: test
   Type: iphash
   References: 0
   Default binding:
   Header: hashsize: 1024 probes: 8 resize: 50
   Members:
   Bindings:

   fwbuilder@guardian:~$ sudo ipset -X test
   fwbuilder@guardian:~$ sudo ipset --list

If something did not work right, the command ``ipset --version`` will print an error message. One typical problem is when kernel module was not compiled and installed or could not be loaded. In this case, this command prints something like this:

.. code-block:: text

   # ipset --version
   ipset v4.1, protocol version 4.
   FATAL: Could not open '/lib/modules/2.6.32-22-generic-pae/extra/xtables-addons/ipset/ip_set.ko': No such file or directory
   ipset v4.1: Couldn't verify kernel module version!

Installing the iptables ipset module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On some versions of Ubuntu, including Lucid (and others?), the ipset tools included with xtables-addons does not properly support the ipset setlist set type which Firewall Builder relies on. Here are instructions for installing only the iptables ipset module and tools.

First, you need to get the ipset module source. You can do this by running the commands shown below.

.. note::

   You will need to be root or have sudo access to run these commands. Depending on what is already installed on your system you might see slightly different command outputs.

.. code-block:: bash

   fwbuilder@guardian:~$ sudo aptitude install ipset-source

Next, you will need to build the ipset module from source. We use the convenient ``module-assistant`` for this. You will see a window pop-up that displays the status of the module being built.

.. code-block:: text

   fwbuilder@guardian:~$ sudo module-assistant build ipset
   Extracting the package tarball, /usr/src/ipset.tar.bz2, please wait...
   Done with /usr/src/ipset-modules-2.6.32-21-generic-pae_2.5.0-1+2.6.32-21.32_i386.deb .

Once this is complete you need to install the debian package that was created by ``module-assistant``.

.. code-block:: bash

   fwbuilder@guardian:~$ sudo dpkg -i \
     /usr/src/ipset-modules-2.6.32-21-generic-pae_2.5.0-1+2.6.32-21.32_i386.deb

Now you need to install the ipset tools.

.. code-block:: bash

   fwbuilder@guardian:~$ sudo aptitude install ipset

Your ipset module installation should now be complete. To confirm that the installation was successful try running the following commands.

.. code-block:: text

   fwbuilder@guardian:~$ sudo ipset --version
   ipset v2.5.0 Protocol version 2.
   fwbuilder@guardian:~$
   fwbuilder@guardian:~$ sudo ipset -N test iphash
   fwbuilder@guardian:~$
   fwbuilder@guardian:~$ sudo ipset --list
   [sudo] password for fwbuilder:
   Name: test
   Type: iphash
   References: 0
   Default binding:
   Header: hashsize: 1024 probes: 8 resize: 50
   Members:
   Bindings:

   fwbuilder@guardian:~$ sudo ipset -X test
   fwbuilder@guardian:~$ sudo ipset --list
