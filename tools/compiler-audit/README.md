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
| `replay-iptables.sh` | does real iptables accept every command? | a command that stops the activation, with the rules behind it never installed |
| `replay-routes.sh` | does iproute2 accept every route? | a route command that fails, which since the routing rollback puts the previous routing table back and stops the activation |
| `check-iptables-restore.sh` | does `iptables-restore --test` accept the restore form? | the same, for firewalls that activate through restore |
| `compare-reference.sh` | do we produce the rules the C++ compiler produced? | rules we get wrong or leave out |
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
tools/compiler-audit/replay-iptables.sh /tmp/audit
tools/compiler-audit/replay-routes.sh /tmp/audit
tools/compiler-audit/check-iptables-restore.sh /tmp/audit
```

`replay-iptables.sh` overwrites the tool paths the script sets for itself.
A firewall may configure its own `/usr/local/sbin/iptables`, which does not
exist here, and then every command fails for a reason that has nothing to do
with the rule - one firewall of the reference corpus hid 393 commands that
way, two of which were real findings.

`check-nft.sh`, `load-nft.sh`, `fill-nft-sets.sh`, `replay-iptables.sh`,
`replay-routes.sh` and `check-iptables-restore.sh` need
`unshare`, `nft` and `iptables`. They run everything in an unprivileged
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
