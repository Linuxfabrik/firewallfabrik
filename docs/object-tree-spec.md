# Object Tree Specification

Reference document for rewriting the FirewallFabrik object tree, based on analysis of the fwbuilder C++ codebase.

## Table of Contents

1. [Global Behavior](#global-behavior)
2. [Per-Object-Type Specification](#per-object-type-specification)
3. [Context Menu State Logic](#context-menu-state-logic)
4. [Drag & Drop Rules](#drag-drop-rules)
5. [Multi-Selection Rules](#multi-selection-rules)

---

## Global Behavior

### Single Click

- **Selects** the object in the tree
- **Adds** the object to the navigation history (back/forward stack)
- Does **NOT** open the editor

### Double Click (= Enter/Return key)

- Opens the object in the editor panel (via `ObjectEditor::open()`)
- System folders are **rejected** (no action)
- RuleSet objects (Policy/NAT/Routing) have special handling: open in **both** RuleSetView AND editor
- When opening a Firewall/Cluster in the editor, automatically switches RuleSetView to the last viewed RuleSet for that firewall

### Right Click

- Shows a context menu whose entries depend on the object type, read-only status, selection count, and hierarchy position
- Context menu always appears at cursor position

### Signal Flow (Double Click)

```
User double-clicks item
  -> ObjectTreeView::edit(DoubleClicked)
  -> emit editCurrentObject_sign()
  -> ObjectManipulator::editSelectedObject()
  -> IF RuleSet:
       -> openRulesetEvent (if not already open)
       -> openObjectInEditorEvent (if editor visible)
     ELSE:
       -> openObjectInEditorEvent
  -> FWWindow::openEditor(obj)
  -> ObjectEditor::open(obj)
  -> QStackedWidget shows correct dialog
```

---

## Per-Object-Type Specification

### Library

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open in editor (shows LibraryDialog) |
| Read-only | Shows "Inspect" instead of "Edit" in context menu |

**Context Menu:**
- Edit / Inspect
- Copy, Cut, Paste
- Delete (only if in user library)
- Undelete (only if in Deleted Objects library)
- Find, Where used
- Lock / Unlock
- Keywords submenu

**Restrictions:**
- Cannot be duplicated
- Cannot be moved (except from Deleted Objects via "Undelete")
- Standard libraries (syslib000, syslib001) are read-only
- Cannot create child objects directly

---

### Firewall

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open FirewallDialog in editor; switch RuleSetView to last viewed RuleSet for this firewall |

**Context Menu:**
- Edit / Inspect
- Duplicate... (to library submenu)
- Move... (to library submenu)
- Copy, Cut, Paste
- Delete
- **New Interface** (if writable)
- **New Policy** (if writable)
- **New NAT** (if writable)
- New Subfolder
- Find, Where used
- Group (if multi-select)
- Keywords submenu
- **New cluster from selected firewalls** (enabled only if multiple Firewalls selected)
- **Compile**, **Install**, **Inspect** (firewall operations)
- Lock / Unlock

**Undo:** All creation/deletion operations use `FWCmdAddObject` / `FWCmdDeleteObject` which are undoable.

---

### Cluster

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open ClusterDialog in editor |

**Context Menu:**
- Edit / Inspect
- Duplicate... (to library submenu)
- Move... (to library submenu)
- Copy, Cut, Paste
- Delete
- **Add cluster interface** (if writable)
- **New State synchronization group** (multiple allowed per cluster)
- **New Policy** (if writable)
- **New NAT** (if writable)
- New Subfolder
- Find, Where used
- Group (if multi-select)
- Keywords submenu
- **New cluster from selected firewalls** (if multiple Firewalls selected)
- **Compile**, **Install**, **Inspect**
- Lock / Unlock

---

### Host

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open HostDialog in editor |

**Context Menu:**
- Edit / Inspect
- Duplicate... (to library submenu)
- Move... (to library submenu)
- Copy, Cut, Paste
- Delete
- **New Interface** (if writable)
- New Subfolder
- Find, Where used
- Group (if multi-select)
- Keywords submenu
- Lock / Unlock

---

### Interface

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open InterfaceDialog in editor |

**Context Menu:**
- Edit / Inspect
- Copy, Cut, Paste
- Delete
- **New Interface** (subinterface, only if parent Firewall supports advanced interfaces AND parent is Firewall, not Cluster; only one level of subinterfaces)
- **New Address** (IPv4)
- **New Address IPv6** (IPv6)
- **New MAC Address** (physAddress)
- **New Attached Networks** (only if not already present on this interface)
- **New Failover Group** (only if parent is Cluster AND not already present)
- Find, Where used
- **Make subinterface of...** submenu (lists non-loopback top-level interfaces)
- Keywords submenu
- Lock / Unlock

**Restrictions:**
- Cannot be duplicated
- Cannot be moved (unless parent host/firewall is also selected)
- No "Duplicate..." or "Move..." submenus shown

---

### Policy / NAT / Routing (RuleSet)

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open in RuleSetView AND editor (RuleSetDialog) |

**Context Menu:**
- Edit / Inspect (opens in editor)
- **Open** (opens in RuleSetView only, unlike "Edit" which opens both)
- Copy, Cut, Paste
- Delete (cannot delete last Policy/NAT/Routing on a Firewall; cannot delete "top" policy)
- Find, Where used
- Keywords submenu
- Lock / Unlock

**Restrictions:**
- Cannot be duplicated
- Cannot be moved
- No "Duplicate..." or "Move..." submenus shown

**Special double-click behavior:**
- If RuleSet is already open in RuleSetView: open in editor if visible
- If RuleSet is not open: open in RuleSetView first, then in editor if visible

---

### IPv4 Address

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open IPv4Dialog in editor |

**Context Menu:**
- Edit / Inspect
- Duplicate... (to library submenu)
- Move... (to library submenu)
- Copy, Cut, Paste
- Delete
- New Subfolder
- Find, Where used
- Group (if multi-select)
- Keywords submenu
- Lock / Unlock

**Input Validation:**
- IPv4 address format validation
- Netmask validation (dotted-decimal or CIDR prefix 0-32)
- CIDR notation auto-parsing (e.g. `192.168.1.1/24` -> address + netmask)

**Restrictions:**
- Cannot be moved if parent is Interface

---

### IPv6 Address

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open IPv6Dialog in editor |

**Context Menu:** Same as IPv4

**Input Validation:**
- IPv6 address format validation
- Prefix length validation (1-127)
- CIDR notation auto-parsing (e.g. `2001:db8::1/64` -> address + prefix)

**Restrictions:**
- Cannot be moved if parent is Interface

---

### Network

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open NetworkDialog in editor |

**Context Menu:**
- Edit / Inspect
- Duplicate... (to library submenu)
- Move... (to library submenu)
- Copy, Cut, Paste, Delete
- New Subfolder
- Find, Where used
- Group, Keywords, Lock / Unlock

**Input Validation:**
- IPv4 address + netmask validation
- CIDR notation auto-parsing (fills network address + netmask)

---

### Network IPv6

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open NetworkDialogIPv6 in editor |

**Context Menu:** Same as Network

**Input Validation:**
- IPv6 address + prefix length validation
- CIDR notation auto-parsing

---

### Address Range

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open AddressRangeDialog in editor |

**Context Menu:** Same as Network

**Input Validation:**
- Start/end IP address validation
- Start and end must be same IP family
- End auto-corrected to >= start
- CIDR notation in start field fills both start (first host) and end (last host)
- When start loses focus: if end is empty or different family, copy start to end

---

### DNS Name

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open DNSNameDialog in editor |

**Context Menu:** Standard (Edit, Duplicate, Move, Copy, Cut, Paste, Delete, Find, Where used, Group, Keywords, Lock/Unlock)

---

### Address Table

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open AddressTableDialog in editor |

**Context Menu:** Standard

---

### Physical Address (MAC)

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open PhysAddressDialog in editor |

**Context Menu:**
- Edit / Inspect
- Copy, Paste (disabled when parent is Interface)
- Delete
- Find, Where used
- Keywords, Lock / Unlock

**Restrictions:**
- Cannot be duplicated
- Cannot be moved
- No Duplicate/Move submenus

---

### Object Group

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open GroupObjectDialog in editor |

**Context Menu:**
- Edit / Inspect
- Duplicate... (to library submenu)
- Move... (to library submenu)
- Copy, Cut, Paste, Delete
- New Subfolder
- Find, Where used
- Group, Keywords, Lock / Unlock
- If name == "Firewalls": also shows Compile, Install, Inspect, New cluster from selected firewalls

---

### Dynamic Group

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open DynamicGroupDialog in editor |

**Context Menu:** Same as Object Group

---

### Service Group

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open GroupObjectDialog in editor |

**Context Menu:** Standard (Edit, Duplicate, Move, Copy, Cut, Paste, Delete, Find, Where used, Group, Keywords, Lock/Unlock)

---

### TCP Service

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open TCPServiceDialog in editor |

**Context Menu:** Standard

**Input Validation:**
- Source/destination port range (0-65535)
- End port auto-corrected to >= start port
- "Established" checkbox disables all TCP flag checkboxes

---

### UDP Service

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open UDPServiceDialog in editor |

**Context Menu:** Standard

**Input Validation:**
- Source/destination port range (0-65535)
- End port auto-corrected to >= start port

---

### ICMP Service / ICMP6 Service

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open ICMPServiceDialog in editor |

**Context Menu:** Standard

---

### IP Service

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open IPServiceDialog in editor |

**Context Menu:** Standard

**Input Validation:**
- "Any option" checkbox disables all IP option checkboxes

---

### Custom Service

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open CustomServiceDialog in editor |

**Context Menu:** Standard

---

### Tag Service

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open TagServiceDialog in editor |

**Context Menu:** Standard

---

### User Service

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open UserServiceDialog in editor |

**Context Menu:** Standard

---

### Time Interval

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open TimeDialog in editor |

**Context Menu:** Standard

**Input Validation:**
- "Use start date" / "Use end date" checkboxes enable/disable respective date pickers

---

### Attached Networks

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open in editor |

**Restrictions:**
- Cannot be duplicated, moved, copied, pasted, or deleted independently
- Only one per Interface
- Auto-managed: created via Interface context menu only

---

### Failover Cluster Group

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open in editor |

**Restrictions:**
- Only creatable under Cluster Interface
- Only one per Interface allowed
- Menu item automatically disabled if already exists

---

### State Sync Cluster Group

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | Open in editor |

**Notes:**
- Multiple allowed per Cluster
- Represents different state synchronization protocols

---

### System Folders (Standard Folders)

Examples: "Firewalls", "Clusters", "Objects", "Objects/Addresses", "Objects/DNS Names", "Objects/Address Tables", "Objects/Address Ranges", "Objects/Groups", "Objects/Hosts", "Objects/Networks", "Services", "Services/Custom", "Services/Groups", "Services/IP", "Services/ICMP", "Services/TCP", "Services/UDP", "Services/Users", "Services/TagServices", "Time"

| Action | Behavior |
|--------|----------|
| Click | Select + history |
| Double-click | **Rejected** (no action) |

**Restrictions:**
- Cannot be edited, duplicated, moved, or deleted
- Context menu: only expand/collapse, paste (if valid), and "New ..." items for child creation

---

## Context Menu State Logic

### Enable/Disable Conditions

| Action | Enabled When |
|--------|-------------|
| Edit | Single selection, not a standard folder |
| Copy | Same parent for all selections, not standard folder, not in Deleted Objects |
| Cut | Same as Delete |
| Paste | Target valid for object type, clipboard not empty, target not read-only |
| Delete | Not read-only, not standard folder, not last Policy/NAT/Routing, not in standard library |
| Duplicate | Not standard folder, not in Deleted Objects, not Library, not Interface, not physAddress, not RuleSet |
| Move | Not standard folder, not Library (except in Deleted), not Interface (unless parent also selected), not physAddress, not read-only |
| New Items | Parent not read-only |
| Find / Where used | Single selection, not standard folder |
| Lock | Object writable, not already locked |
| Unlock | Object locked, parent writable |
| Group | Multiple objects selected |

### Read-Only Rules

- Read-only objects show "Inspect" instead of "Edit"
- Read-only parents prevent creating children
- Standard libraries are always read-only
- The Deleted Objects library is read-only

### Delete Protection for RuleSets

Cannot delete if:
- It's the last Policy on its Firewall
- It's the last NAT on its Firewall
- It's the last Routing on its Firewall
- It's the "top" policy ruleset

---

## Drag & Drop Rules

### What Can Be Dragged

Any non-system object **except**:
- Dummy objects (DUMMY_ADDRESS_ID, DUMMY_SERVICE_ID, DUMMY_INTERFACE_ID)
- User-defined folders (they have no FWObject)

### Objects That Can NEVER Be Dropped in the Tree

- **Interface** objects
- **Objects with Interface parent** (addresses on interfaces)
- **Policy** objects
- **NAT** objects
- **Routing** objects

### Drop Target Validation

1. **Same application only** - drag source must be from the same fwbuilder instance
2. **Not system folders** - cannot drop system folders anywhere
3. **Not from Deleted Objects** - cannot drop objects from Deleted Objects library
4. **Parent matching** - dragged object's parent must match the target's parent or be the target itself
5. **No-op prevention** - dragging to the same location is rejected

### User Folder Drops

- Object's parent must match the folder's parent object
- Must be moving to a different folder (no-op moves rejected)

### Type-by-Type Summary

| Object Type | Draggable | Valid Drop Targets | Notes |
|-------------|-----------|-------------------|-------|
| Firewall | Yes | Groups, "Firewalls" folder, other libraries | |
| Cluster | Yes | Groups, "Clusters" folder, other libraries | |
| Host | Yes | Groups, standard folders, other libraries | |
| Interface | **No** | N/A | Cannot be moved via D&D |
| Policy/NAT/Routing | **No** | N/A | Cannot be moved |
| IPv4/IPv6 Address | Yes | Interfaces, Groups, standard folders | Cannot move if parent is Interface |
| Network/NetworkIPv6 | Yes | Groups, standard folders | |
| Address Range | Yes | Groups, standard folders | |
| DNS Name | Yes | Groups, standard folders | |
| Address Table | Yes | Groups, standard folders | |
| Object Group | Yes | Groups folder, other groups | Contains references |
| Service Group | Yes | "Services/Groups" folder | Contains references |
| TCP/UDP/ICMP/IP/Custom Service | Yes | Service groups, "Services/*" folders | Type-specific destination |
| Tag Service | Yes | "Services/TagServices" folder | |
| User Service | Yes | "Services/Users" folder | |
| Time Interval | Yes | "Time" folder | |
| physAddress | **No** | N/A | Cannot be moved |
| Attached Networks | **No** | N/A | Cannot be moved/copied/duplicated |
| Dummy objects | **No** | N/A | Placeholders, not draggable |

### Drag into Rule Elements (RuleSetView)

- Only **Object** and **Time** column types accept drops
- `RuleElement::validateChild()` must return true
- Cannot drop Any/Dummy elements
- No duplicates: same object ID cannot already exist in RuleElement
- Cannot drop objects from Deleted Objects library
- Interface RuleElements: interface must belong to the firewall being edited

**Drag source behavior in rules:**
- From tree to rule: **Copy** operation
- From rule to rule (same RuleSetView):
  - With Ctrl key: **Copy**
  - Without Ctrl key: **Move** (delete from source, insert at destination)

### Drag Badge

When dragging multiple objects, a red circle badge with the count is shown on the drag pixmap.

---

## Multi-Selection Rules

### Selection Simplification

When multiple items are selected, `getSimplifiedSelection()` removes children if their parent is also selected. This prevents double-processing during moves, deletes, and group operations.

### Multi-Select Context Menu Changes

- **Edit**: Disabled (single-select only)
- **Find / Where used**: Disabled (single-select only)
- **New ...** items: Not shown (single-select only)
- **Group**: Enabled (creates a new group from selection)
- **Copy / Cut / Delete**: Enabled for all selected objects
- **Duplicate / Move**: Enabled (applies to all selected)

### "Group" Action

When multiple objects are selected:
1. Shows `newGroupDialog` with group name and target library
2. Auto-detects group type from first selected object:
   - Service objects -> ServiceGroup
   - Time intervals -> IntervalGroup
   - Everything else -> ObjectGroup
3. Creates new group in selected library's standard slot
4. Adds references (`addRef`) to all selected objects
5. Operation is undoable

### "New cluster from selected firewalls"

- Only enabled when multiple Firewalls are selected
- Also shown when right-clicking the "Firewalls" system folder
- All selected objects must be Firewalls

---

## CRUD Operations

### Create

#### Generic Object Creation
1. Create via `db->create(objType)`
2. If duplicating, copy data from source: `duplicate(copyFrom, true)`
3. Generate unique name: `makeNameUnique(parent, objName, objType)`
4. Wrap in `FWCmdAddObject` for undo support
5. Place in standard slot for type via `FWBTree().getStandardSlotForObject(lib, objType)`

**Validation:**
- Only read-write libraries accepted
- Object type must have a corresponding standard slot in tree

#### Object-Specific Creation Rules

| Object Type | Parent | Special Behavior |
|-------------|--------|-----------------|
| Firewall | Library | Wizard dialog (name, platform, host OS); auto-creates Policy ruleset; can start from template |
| Cluster | Library | Wizard: selects member firewalls, creates interfaces with failover groups, copies rulesets from source, optionally creates backup copies of members |
| Library | Database | Created via `FWBTree().createNewLibrary(db)` |
| Policy/NAT | Firewall/Cluster | Auto-named "Policy", "Policy_1", etc.; sorted alphabetically |
| Interface | Host/Firewall/Cluster or parent Interface (subinterface) | Auto-detects subinterface type; resets to "ethernet" if pasting |
| IPv4/IPv6 | Interface | Standard name pattern: "eth0:ip", "eth0:ip6" |
| physAddress | Interface | Only one per interface; named "iface:mac" |
| AttachedNetworks | Interface | Only one per interface |
| FailoverClusterGroup | Cluster Interface | Only one per interface per protocol |

### Delete

#### Soft Delete (Move to Deleted Objects)
1. Does **NOT** immediately delete — moves object to "Deleted Objects" library
2. Finds all reference holders via `UsageResolver().findAllReferenceHolders()`
3. Removes references from all holders
4. In RuleElements, replaces removed references with dummy objects (DummyAddress, DummyService)
5. Wrapped in `FWCmdMoveObject` with reference_holders map

**Undo:** Restores all references and moves object back to original location.

#### Hard Delete (from Deleted Objects only)
- Only applies to objects already in Deleted Objects library
- Actual removal via `parent->remove(delobj)`
- Object kept referenced for undo

#### Delete Protection
- Cannot delete from standard library
- Cannot delete read-only objects
- Cannot delete last Policy/NAT/Routing ruleset of a firewall

### Clipboard Operations

#### Copy
1. Get simplified selection (no parent-child pairs)
2. Clear clipboard
3. Store (object_id, source_project) pairs
4. System objects cannot be copied

#### Cut
1. Copy to clipboard
2. Soft-delete selected objects (move to Deleted Objects)
3. Both operations wrapped in a single `FWCmdMacro` for atomic undo

#### Paste
1. Target = first selected object
2. Deduplicates by ID (won't paste same object twice)
3. **If target is Group**: add reference via `addRef(obj)` (no duplicate refs)
4. **If target is system group/interface**: full copy via `create()` + `duplicate()`
5. **If from different project**: deep copy of subtree with ID mapping, triggers tree reload
6. Interface pasted to Interface: resets type to "ethernet", clears management flag

#### Duplicate
1. Select target library from submenu
2. Find standard slot for object type in target library
3. Create copy with unique name
4. Open new object in editor

### Update (Property Changes)

- All property changes wrapped in `FWCmdChange`
- Saves old and new state copies for undo/redo
- **Rename**: triggers auto-rename of children (subinterfaces, addresses, MAC)
  - Naming convention: `parent:child:suffix` (e.g., "eth0:ip", "eth0:mac")
- **Lock/Unlock**: sets `readOnly` flag; cannot lock objects in standard library

### Move

- Between libraries: `FWCmdMoveObject` with old/new parent
- To/from user folders: `FWCmdMoveToFromUserFolder`; clears `folder` attribute when moving out
- System objects/interfaces cannot be moved
- Move to Deleted Objects = soft delete (populates reference_holders)

---

## Undo/Redo

All tree operations use the command pattern via `QUndoStack`:

| Operation | Command Class |
|-----------|--------------|
| Create object | `FWCmdAddObject` |
| Delete object (hard) | `FWCmdDeleteObject` |
| Delete object (soft) / Move | `FWCmdMoveObject` |
| Change properties | `FWCmdChange` |
| Rename object | `FWCmdChangeName` (auto-renames children) |
| Lock/Unlock | `FWCmdLockObject` |
| Add subfolder | `FWCmdAddUserFolder` |
| Remove subfolder | `FWCmdRemoveUserFolder` |
| Rename subfolder | `FWCmdMacro` (composite: add new + move children + remove old) |
| Move to/from user folder | `FWCmdMoveToFromUserFolder` |
| Group objects | `FWCmdAddObject` (with refs) |
| Cut | `FWCmdMacro` (copy + soft delete) |

```
FWCmdBasic (base)
  +-- FWCmdChange
  |     +-- FWCmdChangeName
  |     +-- FWCmdLockObject
  |     +-- FWCmdChangeOptionsObject
  +-- FWCmdAddObject
  |     +-- FWCmdAddLibrary
  |     +-- FWCmdAddUserFolder
  +-- FWCmdDeleteObject (hard delete)
  +-- FWCmdMoveObject (soft delete + move)
  +-- FWCmdMoveToFromUserFolder
  +-- FWCmdRemoveUserFolder
  +-- FWCmdMacro (groups multiple commands)
```

Every operation is undoable via Ctrl+Z / Ctrl+Y.

### Post-Operation UI Events

| Event | Trigger |
|-------|---------|
| `insertObjectInTreeEvent` | Add item to tree |
| `removeObjectFromTreeEvent` | Remove item from tree |
| `updateObjectAndSubtreeImmediatelyEvent` | Refresh tree section |
| `openObjectInEditorEvent` | Open editor |
| `dataModifiedEvent` | Mark database dirty |
| `showObjectInTreeEvent` | Show + select in tree |
| `reloadObjectTreeImmediatelyEvent` | Full tree rebuild (cross-project paste) |
| `objectNameChangedEvent` | Trigger auto-rename of children |

---

## Source File References

- `ObjectTreeView.cpp` - Tree widget: click/dblclick handling, drag initiation, drop validation
- `ObjectManipulator.cpp` - Context menu building, edit/open dispatching, menu state logic
- `ObjectManipulator_ops.cpp` - CRUD operations: copy, paste, delete, group, subfolder management
- `ObjectManipulator_create_new.cpp` - Object creation: firewall wizard, generic create, interface create
- `ObjectManipulator_tree_ops.cpp` - Tree management: addLib, insertSubtree, signal connections
- `FWWindow_editor.cpp` - Editor opening, title/icon building, RuleSet auto-switching
- `ObjectEditor.cpp` - Dialog registration and object-to-dialog dispatching
- `FWBTree.cpp` - System folder detection, standard slot lookup, hierarchy validation
- `FWCmdChange.cpp` - Undo/redo command for property changes, rename, lock
- `FWCmdAddObject.cpp` - Undo/redo command for object creation
- `FWCmdDeleteObject.cpp` - Undo/redo command for hard delete
- `FWCmdMoveObject.cpp` - Undo/redo command for soft delete and move
- `newGroupDialog.cpp` - Group creation dialog
