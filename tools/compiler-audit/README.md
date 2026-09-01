# Compiler audit

The expected-output tests in `tests/` guard against *changes* in the compiler
output. They cannot tell you whether that output works, because nothing in
them ever hands a generated script to iptables or nftables.

These tools do exactly that. Each one is an oracle: it takes the generated
scripts and asks a tool that is not FirewallFabrik whether they are any good.
That is where the interesting findings come from, because the failure modes
they expose are the ones an administrator hits at activation time and we do
not.

## The oracles

| Tool | Asks | Finds |
|---|---|---|
| `check-shell-syntax.sh` | does the shell parse this? | a script that does not run at all |
| `check-nft.sh` | does `nft --check` accept this ruleset? | a ruleset that refuses to load, so the firewall keeps its old rules |
| `load-nft.sh` | and does a real kernel take it? | what `--check` never evaluates: a statement in a hook that forbids it, a jump cycle - and nft loads atomically, so the whole ruleset goes |
| `fill-nft-sets.sh` | and do the sets the script fills after the load actually fill? | a named set that stays empty, which is a set no packet is in: a Deny rule that blocks nothing, an Accept rule that lets nothing through |
| `replay-nft-actions.sh` | do the "block" and "stop" actions of an nftables script do what they say? | a block that leaves an address family open or a hook unhooked - the code paths an administrator reaches once something has already gone wrong |
| `replay-iptables.sh` | does real iptables accept every command? | a command that stops the activation, with the rules behind it never installed |
| `replay-address-tables.sh` | are the ipsets an address table needs there by the time the rules that name them are installed? | a `-m set` rule the tool refuses, and a set list left empty - which is a set no packet is in |
| `replay-status.sh` | after a real activation, does the script agree that it is up? | a firewall that answers "status" with "not configured" while its rules are loaded, which an init system and a monitoring check read as dead |
| `replay-twice.sh` | does the second activation leave the same ruleset as the first? | a rule the reset does not recognise as ours, appended again on every activation - one more copy per boot, per change, per reload |
| `replay-interfaces.sh` | does `configure_interfaces` run, run twice, and leave the bridges it named? | an interface block that stops the activation before a rule is installed, or a bridge with ports missing from it |
| `replay-routes.sh` | does iproute2 accept every route? | a route command that fails, which since the routing rollback puts the previous routing table back and stops the activation |
| `check-iptables-restore.sh` | does `iptables-restore --test` accept the restore form? | the same, for firewalls that activate through restore |
| `compare-reference.sh` | do we produce the rules the C++ compiler produced? | rules we get wrong or leave out |
| `compare-order.py` | do the two platforms put one base chain's rules in one order? | a Deny that lands after the Accept it was written above, which no other check can see - first match wins and every other oracle compares sets |
| `parity.py` | do our nftables rules check what `iptables-translate` says they should? | a condition one platform checks and the other does not |
| `parity.py --values` | and do they check it against the same value? | a wrong port, a wrong mask, an inverted operator |
| `compare-output.py` | which firewalls does this change actually affect? | the blast radius of a fix, before a release |

## Running them

```bash
# Compile the fixtures with both compilers.
python tools/compiler-audit/compile-corpus.py /tmp/audit

# Then ask the real tools.
tools/compiler-audit/check-shell-syntax.sh /tmp/audit
tools/compiler-audit/check-nft.sh /tmp/audit
tools/compiler-audit/load-nft.sh /tmp/audit
tools/compiler-audit/fill-nft-sets.sh /tmp/audit
tools/compiler-audit/replay-nft-actions.sh /tmp/audit
tools/compiler-audit/replay-iptables.sh /tmp/audit
tools/compiler-audit/replay-address-tables.sh /tmp/audit
tools/compiler-audit/replay-status.sh /tmp/audit
tools/compiler-audit/replay-twice.sh /tmp/audit
tools/compiler-audit/replay-routes.sh /tmp/audit
tools/compiler-audit/replay-interfaces.sh /tmp/audit
tools/compiler-audit/check-iptables-restore.sh /tmp/audit
```

`replay-iptables.sh` calls `script_body` and nothing above it, so the
block that creates the ipsets of a run-time address table never runs and
every `-m set` rule of such a firewall is refused with
`Set <name> doesn't exist`.  That is the oracle's own blind spot and not
a finding; `replay-address-tables.sh` is the one that runs the loading
first and then asks whether the sets are there.

`replay-iptables.sh` overwrites the tool paths the script sets for itself.
A firewall may configure its own `/usr/local/sbin/iptables`, which does not
exist here, and then every command fails for a reason that has nothing to do
with the rule - one firewall of the reference corpus hid 393 commands that
way, two of which were real findings.

`check-nft.sh` and `load-nft.sh` give the namespace a passwd file of its
own, holding every user and group a `meta skuid` / `meta skgid` in the
ruleset names. nft looks the name up with `getpwnam` while it parses the
rule and refuses the **whole** ruleset when the answer is no, and the
firewall those rules are for has that user where this machine has no
reason to - without the passwd file the check reports the ruleset for a
property of the host it runs on. It still reports everything else: point
it at a ruleset with an invented user *and* a bad address and only the
address comes back.

`check-nft.sh`, `load-nft.sh`, `fill-nft-sets.sh`, `replay-nft-actions.sh`,
`replay-iptables.sh`, `replay-address-tables.sh`, `replay-interfaces.sh`,
`replay-routes.sh`, `replay-status.sh`, `replay-twice.sh` and
`check-iptables-restore.sh` need `unshare`, `nft` and `iptables`
(`replay-address-tables.sh` also needs `ipset`). They run everything in an unprivileged
private network namespace, so nothing touches the machine's own firewall.
Without the namespace `nft --check` fails with "cache initialization failed:
Operation not permitted", because it cannot open a netlink socket.

`compile-corpus.py` writes `report.json` next to the scripts, holding the
errors and warnings of every firewall. Ranking those by frequency is the
fastest way to decide what to look at next:

```bash
python - <<'EOF'
import collections, json, re
report = json.load(open('/tmp/audit/report.json'))
counter = collections.Counter()
for run in report.values():
    for error in run.get('errors', []):
        counter[re.sub(r'\d+', 'N', error)] += 1
for message, n in counter.most_common(20):
    print(f'{n:5d}  {message}')
EOF
```

## Comparing against Firewall Builder

`compare-reference.sh` needs a Firewall Builder checkout, because the
reference output lives beside its regression suite:

```bash
export FWF_FWBUILDER_REFERENCE=~/git/fwbuilder/fwbuilder5/test/ipt
tools/compiler-audit/compare-reference.sh /tmp/audit
```

Read the two columns separately. **missing** counts reference rules we do not
produce and must never grow — a correct fix leaves it untouched. **extra**
counts rules the reference never emitted, and dropping it is what progress
looks like. A single total hides both.

Every firewall of the corpus is compiled, and a **cluster** is compiled the
way Firewall Builder compiles one: once per member, with the cluster named
alongside, written as `<cluster>_<member>.fw`. That is how its reference
output is named, so those 15 scripts are compared too. Without a fixture
name `compare-reference.sh` searches every fixture directory, which is what
finds them. Two reference files are skipped there and say why in the
script: `linux-1.fw.orig` and `linux-2.fw.orig` are member compiles saved
under the bare member name, and nothing in them says which cluster.
**A baseline taken before 2026-08-29 did not include the cluster members
and is not comparable.**

`compare-reference.sh` counts `$IPTABLES` lines and a route installs none,
so the routing block is invisible to it; `replay-routes.sh` is what reads
that half.

Only `script_body()` is compared, because that is the function both compilers
install the policy from. The reset helpers, the coexistence jump setup,
`check_tools` and the block/stop actions hold `$IPTABLES` too, exist in every
script and differ by design; counting them added about 2000 to `missing` and
6800 to `extra` and hid the number that means something. **A baseline taken
before 2026-08-21 was measured the old way and is not comparable.**

The number is pessimistic on purpose: a rule wrapped in a run-time loop (an
address table, a dynamic interface address) is no longer a plain command line
and counts as missing even though it is right.

## Comparing the order the rules are installed in

Both metrics above compare *sets* of rules, and so do `parity.py` and every
tool oracle. First match wins in both packet filters, so a Deny that lands
after the Accept it was written above is a different firewall and none of
them can see it.

```bash
python tools/compiler-audit/compare-order.py /tmp/audit
python tools/compiler-audit/compare-order.py /tmp/audit \
    --reference ~/git/other/fwbuilder/fwbuilder5/test/ipt
```

The comparison is per **base chain**, which is where the order decides
something: a user chain is reached by a jump whose position in the base
chain is what was compared, and its name differs between the compilers
anyway. Only the labels both sides carry are compared, so a rule one
platform reports and leaves out belongs in the `report.json` ranking and
not here.

**Clean as of 2026-08-31**, in both directions: 227 scripts against the
nftables output and 132 against the Firewall Builder reference.

## Compiling with one iptables release pinned

About fifteen matches are gated on the release a firewall names, and the
corpus reaches only a few of the gates: its four data files carry eight
distinct releases between them and 148 firewalls that name none at all.

```bash
python tools/compiler-audit/compile-corpus.py /tmp/v18 --iptables-version 1.8.11
tools/compiler-audit/replay-iptables.sh /tmp/v18
```

Forced to a release current iptables still speaks, this is also what takes
the old-spelling noise out of the replay: `-dport`, `-d !` and the rest are
right for the release they were written for and refused by the tool that
runs here, and they drown everything else.

**Swept 2026-08-31 with 1.8.11 forced**: `bash -n` 456/0, the rule order
unchanged, `iptables-restore --test` 6 rejections down to 2, and every
remaining replay class already known (`-m owner --uid-owner` and `-m set`
are the namespace's own limits, `-m dstlimit` and `-m ipv4options` are
modules netfilter does not carry).  The only errors the compiler gained are
the six optitest rules whose Time object stores the year 2935093, which the
nftables compiler already refused - the two platforms agree once they are
given the same release.

## Compiling one address family at a time

`--address-family 4` and `--address-family 6` compile the corpus the way
the compiler's own `-4` / `-6` switch does.  Put together, the two halves
have to hold every rule the dual-stack run holds: a pass that reads
something the other pass left behind, or that drops a rule because the
other family took it, shows up as a rule that is in the dual run and in
neither half.

```bash
python tools/compiler-audit/compile-corpus.py /tmp/both
python tools/compiler-audit/compile-corpus.py /tmp/v4 --address-family 4
python tools/compiler-audit/compile-corpus.py /tmp/v6 --address-family 6
```

Compare the *multiset* of rule-installing lines per firewall, and read the
two directions separately.  Nothing may be missing from the two halves.
The other direction is expected and not a finding: an automatic rule that
names no address family - "accept established and related", the invalid-state
drop, the TCP-MSS clamp - is written once per pass, so each half carries its
own copy where the dual-stack run needs only one, and on nftables both
families share one `inet` table.

**Clean on both platforms as of 2026-08-31** (nothing missing from either
half over 456 scripts), so do not rebuild it; re-run it after anything
that touches the address-family loop or the automatic rules.

## Measuring the blast radius of a change

Before a release, compile the same corpus with the old and the new compiler
and diff the two trees:

```bash
git worktree add /tmp/before v1.9.0
PYTHONPATH=/tmp/before/src python tools/compiler-audit/compile-corpus.py /tmp/out-before
python tools/compiler-audit/compile-corpus.py /tmp/out-after
python tools/compiler-audit/compare-output.py /tmp/out-before /tmp/out-after
```

Only lines that append a rule are compared, and the nftables `counter`
statement is normalised away. Both matter: without them an unchanged corpus
reads as a hundred percent changed, because `counter` decides nothing and
`reset_all` contains `$IPTABLES` without installing a rule.

Every nftables rule is compared together with the table and chain it sits
in. An iptables command names its chain (`-A input`), an nft rule only has
the block around it, so without that the whole policy of a firewall can
move from the filter table to the mangle table and read as no change at
all. **Check a hundred percent against a plain `diff` before believing
it.**

## Using your own corpus

`--corpus` takes a data file, a directory of them, or a file listing one path
per line, so a set of real configurations can be measured without naming it
here:

```bash
python tools/compiler-audit/compile-corpus.py /tmp/audit --corpus ~/my-firewalls.txt
```

An address table names its data file relative to its own `.fwb` or `.fwf`, so
the shell oracles need `FWF_AUDIT_DATA_DIR` pointing at that directory when
the corpus lives outside `tests/fixtures`.

## Reading the output

Not every line these tools print is a compiler bug, and `replay-iptables.sh`
is the noisiest. A corpus may pin an iptables release current iptables no
longer speaks, name a match module this kernel does not have, use an
extension that never was in mainline, or a uid that `unshare -r` does not map
— it maps only the calling user to root. Check a finding against the Firewall
Builder reference output and the netfilter sources before treating it as one.
