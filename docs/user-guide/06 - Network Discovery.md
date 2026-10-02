# Network Discovery

> [!NOTE]
> SNMP-based object discovery and importing from /etc/hosts files are not available in FirewallFabrik. To populate your object tree, create objects manually (see [05 - Working with Objects](05%20-%20Working%20with%20Objects.md)), open a Firewall Builder file (see [17 - Migrating from Firewall Builder](17%20-%20Migrating%20from%20Firewall%20Builder.md)), or import the ruleset of a running firewall as described below.

## Importing an Existing Firewall Configuration

File \> Import Firewall... builds a firewall object, its interfaces, the address and service objects its rules need and its rule sets from the ruleset a Linux firewall is running. It reads both packet filters:

- the output of `iptables-save` and `ip6tables-save`
- the output of `nft -j list ruleset`

The wizard has four steps.

1. **Choose the ruleset to import.** Either select one or more files saved on the firewall, for example `iptables-save > v4.txt`, `ip6tables-save > v6.txt` or `nft -j list ruleset > ruleset.json`, or let FirewallFabrik read the running firewall over SSH. Over SSH it also reads the addresses of the interfaces (`ip -j addr`), the routes (`ip -j route`) and the packet filter release. The user has to be root, or be allowed to run nft, iptables-save and ip6tables-save with `sudo` without a password. Nothing on the firewall is changed.
2. **Choose the tables to import.** Every table of the input is listed; the filter and nat tables with rules are checked. A table written by iptables-nft shows its matches only as `xt` in the nftables listing, so it is better imported from the iptables-save output. Read over SSH, the main routing table is listed as well (see below). Choose the platform the new firewall is compiled for; it does not have to be the one the ruleset was read from.
3. **Enter firewall object name.** With "Find and use existing objects" checked, an address or service the data file already has, the Standard library included, is used instead of a copy.
4. **Import.** The log lists every rule that could not be carried over exactly. The new firewall opens in the editor.

How the ruleset is mapped:

| In the ruleset | In FirewallFabrik |
|----|----|
| The built-in chains of the filter table (input, forward, output) | One top Policy rule set; the chain becomes the direction of the rule, and the firewall object the destination of an input rule and the source of an output rule |
| The nat table | One top NAT rule set |
| A chain of your own | A rule set of its own, reached by a rule with the Branch action |
| A rule naming an incoming and an outgoing interface, a connection state next to a service, or a user next to a service | A rule that branches into a rule set of its own holding the rest of the match, because one FirewallFabrik rule has one interface and one service element |
| A LOG rule followed by the rule it logs for | One rule with logging on |
| The rules every built-in chain starts with: accept established and related packets, log and drop invalid packets | The firewall options of the same name |
| A built-in chain with policy ACCEPT | A last rule that accepts what the chain accepted |
| A named nftables set of addresses | A group of address objects |

The addresses of the interfaces are not part of a ruleset. Read from a file, every interface the rules name is a dynamic interface, whose addresses the generated script finds when it runs, and every address an input rule names as destination, or an output rule as source, goes on an interface named "imported", because a packet in those chains is addressed to or sent by the firewall itself. Move those addresses to the interfaces they belong to. Read over SSH, the interfaces carry the addresses the machine has.

The routes become the rules of the Routing rule set. A firewall script with routing rules takes over the main routing table: when it starts, it deletes every route of that table it does not install, except the routes the kernel makes for the addresses of the interfaces and, while it installs none of its own, the default route. So the importer takes the routes an administrator configured, which the kernel marks `proto boot` (`ip route add`, ifupdown) or `proto static` (NetworkManager, systemd-networkd). It leaves out and reports:

- routes of DHCP, router advertisements or a routing daemon, which belong to that program
- route types a routing rule cannot hold, such as `throw`
- routes of other tables, which the script leaves alone

A `blackhole`, `unreachable` or `prohibit` route of the main table stops the packets it matches, which no routing rule can do, and the script would delete it. It becomes two rules at the top of the Policy instead, one for the packets the firewall forwards and one for those it sends itself, which drop the packets (`blackhole`) or reject them with the ICMP message the kernel sends (`unreachable`: host unreachable, for IPv6 no route; `prohibit`: administratively prohibited). A more specific route inside it and an address of the firewall in it are routed on rather than stopped, so the rules branch into a rule set that returns those first. The rules are colored; like every rule, they come after the accepted established connections.

Where the main table holds such a route, the routes are not checked in step 2, because installing them would delete it. ifupdown's DHCP client (`dhclient`, Debian 11 and 12) installs the default route with `ip route add`, which the kernel marks `proto boot` like a configured one; it is imported as a fixed route to the gateway the lease named, so remove it from the Routing rule set where the gateway can change. A route with several next hops becomes one rule per hop, which the compiler installs as one multi path route. A route with something a routing rule cannot hold, such as a preferred source address (`src`) or an MTU, is imported colored and with the original in its comment; one through a gateway that is not on the network of its interface (`onlink`) is imported disabled.

The imported firewall has the options that add rules of their own switched off, unless the ruleset showed them: it is meant to do what the old firewall did and nothing more.

A rule the importer cannot carry over exactly, for example one with a match of the `recent`, `length` or `mark` module, a negated port, a time window or a statement of the mangle table, errs on the side of blocking. A rule that accepts or translates traffic is imported disabled, so less passes. A rule that drops or rejects is imported active, without the part that could not be carried over, so it blocks more than the original, never less; disabling it would let through what the original stopped. Both are colored red, and the comment holds the original rule and what is missing. Review these rules, and compare the imported policy with the original before you install it; the rollback timer of the installer (see [10 - Compiling and Installing a Policy](10%20-%20Compiling%20and%20Installing%20a%20Policy.md)) puts the old ruleset back if the new one locks you out.
