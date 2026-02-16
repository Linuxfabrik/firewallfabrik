# Design Decisions

## PySide6 vs. PyQt6

There is no strong technical reason to prefer PySide6 over PyQt6 for this project -- both frameworks are perfectly suitable. We chose PySide6 primarily because FirewallFabrik is being ported from the original Firewall Builder C++/Qt codebase. PySide6's API closely mirrors C++ Qt, which makes the porting process more straightforward and keeps the Python code visually and structurally similar to the original implementation.

Additionally, PySide6 is licensed under the LGPL, which is more permissive and leaves the door open for potential proprietary extensions in the future.


## Removal of the "Deleted Objects" Feature from Firewall Builder

In Firewall Builder, the "Deleted Objects" feature provides only very limited value. When an object is deleted, all references to it are immediately removed. As a result, restoring an object from "Deleted Objects" does not restore its original relationships, significantly reducing the usefulness of the feature.

For this reason, we decided not to implement "Deleted Objects" in FirewallFabrik. Instead, we recommend using Git as a version control system. With the switch from an XML-based backend (Firewall Builder) to YAML (FirewallFabrik), Git makes it easy to restore deleted objects -- including all their references -- by reverting or inspecting previous revisions of the data files.


## Changed Default for "IPv4 Packet Forwarding"

The host settings default for "IPv4 Packet forwarding" was changed from "On" to "No change". This option is only needed for firewalls that actually forward traffic, so it should not be set by default.


## The "linux24" Identifier

The names and identifiers "linux24", "Linux2.4/2.6", "Linux" all refer to the same host OS and do not correspond to a specific Linux version. These names are kept for backward compatibility.
