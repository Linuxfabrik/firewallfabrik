# FirewallFabrik

FirewallFabrik is a Qt-based GUI tool for managing firewall configurations across multiple platforms (iptables, nftables, etc.). Firewall configuration data is stored in a central file that can scale to hundreds of firewalls managed from a single UI.


## Installation

### From PyPI (Recommended)

FirewallFabrik releases are available from [PyPI](https://pypi.org/project/firewallfabrik/).

Using [pipx](https://pipx.pypa.io):

```shell
pipx install firewallfabrik
```

Using standard pip (user install):

```shell
pip install --user firewallfabrik
```

Please note that on certain Linux systems `--break-system-packages`
might need to be added when using the system's Python/Pip.


### From Git (For Development or Power Users)

* Clone this repository.
* To install FirewallFabrik, at the root of the repo, run `pip install .`
* For development use `--editable` to install FirewallFabrik in [Development/Editable Mode](https://setuptools.pypa.io/en/latest/userguide/development_mode.html).
* The usage of a virtual environment is *strongly recommended*.

For example:

```bash
python3.14 -m venv $HOME/venvs/firewallfabrik
source $HOME/venvs/firewallfabrik/bin/activate
pip install --editable .

# run
fwf
```


## Documentation

User Guide:

* [01 - Introduction](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/01%20-%20Introduction.rst>)
* [02 - Installing Firewall Builder](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/02%20-%20Installing%20Firewall%20Builder.rst>)
* [03 - Definitions and Terms](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/03%20-%20Definitions%20and%20Terms.rst>)
* [04 - Firewall Builder GUI](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/04%20-%20Firewall%20Builder%20GUI.rst>)
* [05 - Working with Objects](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/05%20-%20Working%20with%20Objects.rst>)
* [06 - Network Discovery](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/06%20-%20Network%20Discovery.rst)
* [07 - Firewall Policies](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/07%20-%20Firewall%20Policies.rst)
* [08 - Cluster Configuration](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/08%20-%20Cluster%20Configuration.rst)
* [09 - Configuration of Interfaces](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/09%20-%20Configuration%20of%20Interfaces>.rst)
* [10 - Compiling and Installing a Policy](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/10%20-%20Compiling%20and%20Installing>.rst)
* [11 - Manage your Firewall Remotely](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/11%20-%20Manage%20your%20Firewall>.rst)
* [12 - Integration with OS Running on the Firewall Machine](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/12%20-%20Integration%20with%20OS>.rst)
* [13 - Configlets](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/13%20-%20Configlets.rst)
* [14 - Firewall Builder Cookbook](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/14%20-%20Firewall%20Builder%20Cookbook>.rst)
* [15 - Troubleshooting](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/15%20-%20Troubleshooting.rst)
* [16 - Appendix](https://github.com/Linuxfabrik/firewallfabrik/blob/main/docs/user-guide/16%20-%20Appendix.rst)


## Design Decisions

PySide6 vs. PyQt6

* There is no strong technical reason to prefer PySide6 over PyQt6 for this project - both frameworks are perfectly suitable. We chose PySide6 primarily because FirewallFabrik is being ported from the original Firewall Builder C++/Qt codebase. PySide6's API closely mirrors C++ Qt, which makes the porting process more straightforward and keeps the Python code visually and structurally similar to the original implementation.
* Additionally, PySide6 is licensed under the LGPL, which is more permissive and leaves the door open for potential proprietary extensions in the future.

Removal of the "Deleted Objects" Feature from Firewall Builder

* In Firewall Builder, the "Deleted Objects" feature provides only very limited value. When an object is deleted, all references to it are immediately removed. As a result, restoring an object from "Deleted Objects" does not restore its original relationships, significantly reducing the usefulness of the feature.
* For this reason, we decided not to implement "Deleted Objects" in FirewallFabrik. Instead, we recommend using Git as a version control system. With the switch from an XML-based backend (Firewall Builder) to YAML (FirewallFabrik), Git makes it easy to restore deleted objects - including all their references - by reverting or inspecting previous revisions of the data files.


## License

```python
# Copyright (C) 2026 Linuxfabrik <info@linuxfabrik.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# On Debian systems, the complete text of the GNU General Public License
# version 2 can be found in /usr/share/common-licenses/GPL-2.

# SPDX-License-Identifier: GPL-2.0-or-later
```
