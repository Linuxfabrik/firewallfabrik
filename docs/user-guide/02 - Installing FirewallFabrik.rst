Installing FirewallFabrik
=========================

.. sectnum::
   :start: 2

.. contents::
   :local:
   :depth: 2


Requirements
------------

FirewallFabrik requires **Python 3.14** or later. The GUI additionally requires **PySide6** (Qt6 for Python).


Installing from PyPI
---------------------

The recommended way to install FirewallFabrik is from PyPI. Make sure to include the ``[gui]`` extra to pull in PySide6 for the graphical interface.

Using uv (recommended)
~~~~~~~~~~~~~~~~~~~~~~~

You can run FirewallFabrik without a permanent install:

.. code-block:: bash

   uvx --from 'firewallfabrik[gui]' fwf

Or install it as a tool:

.. code-block:: bash

   uv tool install 'firewallfabrik[gui]'

Using pipx
~~~~~~~~~~

.. code-block:: bash

   pipx install 'firewallfabrik[gui]'

Using pip
~~~~~~~~~

.. code-block:: bash

   pip install --user 'firewallfabrik[gui]'

On certain Linux distributions that protect the system Python environment, you may need to add the ``--break-system-packages`` flag.


CLI-Only Installation (No GUI)
-------------------------------

If you only need the command-line compilers (``fwf-ipt``, ``fwf-nft``) and do not need the graphical interface, you can install without the ``[gui]`` extra. This avoids pulling in PySide6:

.. code-block:: bash

   pip install firewallfabrik


Installing from Git
--------------------

For development or to run the latest code from the repository:

.. code-block:: bash

   python3.14 -m venv $HOME/venvs/firewallfabrik
   source $HOME/venvs/firewallfabrik/bin/activate
   pip install --upgrade pip
   pip install --editable '.[gui]'
   fwf

To also install development dependencies (e.g. pytest), add ``--group dev``:

.. code-block:: bash

   pip install --editable '.[gui]' --group dev


Using Native PySide6 on Linux
-------------------------------

Some Linux distributions ship a native PySide6 package that integrates better with the desktop theme (e.g. ``python3-pyside6`` on Fedora). To use it instead of the PyPI version:

1. Install the distribution's PySide6 package, for example:

   .. code-block:: bash

      dnf install python3-pyside6

2. Install FirewallFabrik **without** the ``[gui]`` extra so it does not pull in a separate PySide6 from PyPI:

   .. code-block:: bash

      pip install firewallfabrik

3. If you are using ``pipx``, ``uv tool``, or a virtual environment, initialize it with ``--system-site-packages`` so the native PySide6 is inherited.


Linux Desktop Integration
--------------------------

To add FirewallFabrik to your application menu and associate its icon:

.. code-block:: bash

   cp assets/ch.linuxfabrik.firewallfabrik.desktop $HOME/.local/share/applications/
   mkdir -p $HOME/.local/share/icons/hicolor/scalable/apps/
   cp src/firewallfabrik/gui/ui/Icons/firewallfabrik.svg \
       $HOME/.local/share/icons/hicolor/scalable/apps/ch.linuxfabrik.firewallfabrik.svg
   update-desktop-database $HOME/.local/share/applications/ 2>/dev/null
   gtk-update-icon-cache $HOME/.local/share/icons/hicolor/ 2>/dev/null

If ``fwf`` is installed inside a virtual environment and is not on your system ``PATH``, update the desktop file to use the full path:

.. code-block:: bash

   sed -i "s|Exec=fwf|Exec=$VIRTUAL_ENV/bin/fwf|" \
       $HOME/.local/share/applications/ch.linuxfabrik.firewallfabrik.desktop


Running FirewallFabrik
-----------------------

After installation, launch the GUI with:

.. code-block:: bash

   fwf

To open a specific database file on startup:

.. code-block:: bash

   fwf myconfig.fwf
   fwf -f myconfig.fwf

FirewallFabrik can also open Firewall Builder XML files (``.fwb``) directly.

To check the installed version:

.. code-block:: bash

   fwf --version

Both X11 and Wayland display servers are supported.


Available Commands
-------------------

FirewallFabrik provides the following commands:

``fwf``
   The graphical interface (requires the ``[gui]`` extra).

``fwf-ipt``
   Command-line compiler for iptables configurations.

``fwf-nft``
   Command-line compiler for nftables configurations.
