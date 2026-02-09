# FirewallFabrik

FirewallFabrik is a Qt-based GUI tool for managing firewall configurations across multiple platforms (iptables, nftables, etc.). Firewall configuration data is stored in a central file that can scale to hundreds of firewalls managed from a single UI.


## Installation

```bash
pip --user --requirements requiements.txt
```


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
