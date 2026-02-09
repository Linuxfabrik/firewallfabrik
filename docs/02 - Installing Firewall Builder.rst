.. sectnum::
   :start: 2

Installing Firewall Builder
============================

.. contents::
   :local:
   :depth: 2


RPM-Based Distributions (Red Hat, Fedora, OpenSUSE, and Others)
----------------------------------------------------------------

Using pre-built binary RPM

You need to download and install the Firewall Builder RPM:

* Example: ``fwbuilder-4.2.2.3541-1.el5.i386.rpm``

To satisfy dependencies, you need the following packages installed on your system:

* libxml2 v2.4.10 or newer
* libxslt v1.0.7 o newer
* ucd-snmp or net-snmp
* QT 4.3.x, 4.4.x, 4.5.x, 4.6.x. Firewall Builder uses features available in QT 4.3 and later; the system does not support version 4.2 and earlier.

Pre-built binary RPMs for RedHat Enterprise Linux 5 (RHEL 5) and CentOS 5.x

These distributions do not come with QT4, and third-party binary RPMs of QT v4.3.x and 4.4.x can be difficult to obtain. For these distributions, we distribute binary RPMs of Firewall Builder 4.0 statically linked with QT 4.4.1. These RPMs are posted in the Downloads area of the SourceForge project site. These RPMs have the same standard names ``fwbuilder-4.2.2.3541-1.el5.i386.rpm``, but they have no dependency on QT RPMs.

If a Firewall Builder V3.0 distribution statically linked with QT crashes on start on your CentOS system, please upgrade to the latest version of Firewall Builder. If you need to run Firewall Builder V3.0 please make sure you have the following font packages installed: ``bitmap-fonts`` or ``bitstream-vera-fonts``. Either one resolves the issue and will enable Firewall Builder to work.

To install Firewall Builder, navigate to your download directory and execute the following command (replacing the filename with the name of the files you actually downloaded):

.. code-block:: bash

   rpm -i fwbuilder-4.0.0-1.i386.rpm


Ubuntu Installation
--------------------

Using pre-built binary packages

You need to download and install the Firewall Builder package:

* Example: ``fwbuilder_4.2.2.3541-ubuntu-karmic-1_i386.deb``

To satisfy dependencies, you need the following packages installed on your system:

* QT 4.3.x, 4.4.x, 4.5.x, 4.6.x. Firewall Builder uses features available in QT 4.3 and later; the system does not support version 4.2 and earlier.

You can obtain QT using your favorite package manager.

To install Firewall Builder, go to your download directory and execute the following command (replacing the filenames with the names of the files you actually downloaded):

.. code-block:: bash

   dpkg -i fwbuilder_4.2.2.3541-ubuntu-karmic-1_i386.deb


Installing FreeBSD and OpenBSD Ports
-------------------------------------

Firewall Builder consists of two ports: ``/usr/ports/security/libfwbuilder`` and ``/usr/ports/security/fwbuilder``. Once both ports are updated (which typically takes two to three weeks after the package is released), simply install the port as usual using ``portinstall`` or issuing the ``make install`` command in ``/usr/ports/security/fwbuilder``.


Windows Installation
---------------------

To install onto a Windows system, double-click the package file, then follow the step-by-step instructions in the Installation wizard.


Mac OS X Installation
----------------------

The Mac OS X package is distributed in the form of a disk image (that is, a ``.dmg`` file). Double-click the image to mount it, then drag the Firewall Builder application to your ``Applications`` folder (or any other location).


Compiling from Source
----------------------

Firewall Builder can be compiled and works on the following OS and distributions: Debian Linux (including Ubuntu), Mandrake Linux, RedHat Linux, SuSE Linux, Gentoo Linux, FreeBSD, OpenBSD, Mac OS X, and Solaris.

To compile from source, first download the dependencies for your platform:

For RedHat-based systems:

* ``automake``
* ``autoconf``
* ``libtool``
* ``libxml2-devel``
* ``libxslt-devel``
* ``net-snmp-devel``
* ``qt``
* ``qt-devel``
* ``qt-x11``

You may need to install the packages ``elfutils-libelf`` and ``elfutils-libelf-devel`` (``libelf`` on SuSE), otherwise ``libfwbuilder`` does not pick up the ``net-snmp`` library even if it is installed.

For Debian-based systems:

* ``automake``
* ``autoconf``
* ``libtool``
* ``libxml2-dev``
* ``libxslt-dev``
* ``libsnmp-dev``
* ``libqt4-core``
* ``libqt4-dev``
* ``libqt4-gui``
* ``qt4-dev-tools``

Next, download the source archives from SourceForge, for example ``fwbuilder-4.2.2.3541.tar.gz``, and unpack them to a location. Then build as follows:

.. code-block:: bash

   cd /fwbuilder-<version_number>
   ./autogen.sh
   make
   make install


Compilation may require other packages for RedHat and SuSE
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you observe errors that refer to missing ``autoconf`` macros while running ``autogen.sh`` for ``fwbuilder``, check to ensure your system includes RPM ``gettext-devel``. You may need to add other "development" RPMs besides these, but these two are often forgotten.

The configure scripts for ``fwbuilder`` tries to find your QT4 installation in several standard places. However, if you installed QT in a directory where the script is unable to find it, you can provide the path to it using the ``--with-qtdir`` option to script ``autogen.sh``, as in the following example:

.. code-block:: bash

   cd /fwbuilder-<version_number>
   ./autogen.sh --with-qtdir=/opt/qt4
   make
   make install

By default, script configure assumes ``prefix="/usr/local"`` and installs libraries in ``/usr/local/lib`` and binaries in ``/usr/local/bin``. Make sure ``/usr/local/lib`` is added to your ``LD_LIBRARY_PATH`` environment variable or to the ``/etc/ld.so.conf`` configuration file; otherwise the program will be unable to find dynamic libraries there. Likewise, ``/usr/local/bin`` must be included in your PATH.

You can install libraries and binaries in a different place by specifying a new prefix, as follows:

.. code-block:: bash

   ./autogen.sh --prefix="/opt"

This command installs libraries in ``/opt/lib`` and the program in ``/opt/bin``.
