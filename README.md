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

Clone this repository and run `pip install .` at the root of the repo to install FirewallFabrik.

For development use `--editable` to install FirewallFabrik in
[Development/Editable Mode](https://setuptools.pypa.io/en/latest/userguide/development_mode.html).
The usage of a virtual environment is *strongly recommended*.
For example:

```bash
python3.14 -m venv venv
source venv/bin/activate
pip install --editable .

# run
fwf
```



## Documentation

User Guide:

* :doc:`docs/01 - Introduction`
* :doc:`docs/02 - Installing Firewall Builder`
* :doc:`docs/03 - Definitions and Terms`
* :doc:`docs/04 - Firewall Builder GUI`
* :doc:`docs/05 - Working with Objects`
* :doc:`docs/06 - Network Discovery`
* :doc:`docs/07 - Firewall Policies`
* :doc:`docs/08 - Cluster Configuration`
* :doc:`docs/09 - Configuration of Interfaces`
* :doc:`docs/10 - Compiling and Installing a Policy`
* :doc:`docs/11 - Manage your Firewall Remotely`
* :doc:`docs/12 - Integration with OS Running on the Firewall Machine`
* :doc:`docs/13 - Configlets`
* :doc:`docs/14 - Firewall Builder Cookbook`
* :doc:`docs/15 - Troubleshooting`
* :doc:`docs/16 - Appendix`


## PySide6 vs PyQt6

There's no strong technical reason to choose PySide6 over PyQt6 for this project. Both are viable. We use PySide6 since we're porting from the original Firewall Builder C++ Qt code. When porting to Python, PySide6 code looks almost identical to the original C++ Qt code. The LGPL is a plus since it is more permissive if we ever want to allow proprietary extensions.


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
