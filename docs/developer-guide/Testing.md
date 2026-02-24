# Testing

FirewallFabrik uses **expected output regression tests** to catch unintended changes in compiler output. Each test compiles a fixture (`.fwf` or `.fwb`) with the iptables and/or nftables drivers, normalizes the output, and compares it against a checked-in expected output file.

## Quick Start

```bash
# Install the package with GUI support and test dependencies
pip install --editable ".[gui]"
pip install pytest

# Run all tests
pytest --verbose

# Run only iptables or nftables tests
pytest --verbose tests/test_compiler_ipt.py
pytest --verbose tests/test_compiler_nft.py
```

## Directory Structure

```
tests/
├── conftest.py                          # Shared fixtures (compile helpers, test case discovery)
├── normalize.py                         # Output normalization (strip timestamps, chain hashes, etc.)
├── update_expected_output.py            # Script to regenerate expected output files
├── fixtures/                            # Test data (one per feature or test suite)
│   ├── basic_accept_deny.fwf            # Hand-crafted YAML fixture
│   ├── cluster-tests.fwb               # C++ cluster regression suite (XML)
│   ├── compiler-tests.fwf              # Hand-crafted YAML fixture
│   ├── objects-for-regression-tests.fwb # C++ Firewall Builder regression suite (XML)
│   ├── optimizer-test.fwb              # C++ optimizer regression suite (XML)
│   └── reject_actions.fwf             # Hand-crafted YAML fixture
├── expected-output/
│   ├── ipt/                             # Expected iptables output (normalized)
│   │   ├── basic_accept_deny/
│   │   │   └── fw-test.fw
│   │   ├── cluster-tests/              # 18 C++ reference expected output files
│   │   ├── objects-for-regression-tests/ # 105 C++ reference expected output files
│   │   ├── optimizer-test/             # 2 C++ reference expected output files
│   │   └── ...
│   └── nft/                             # Expected nftables output (normalized)
│       └── basic_accept_deny/
│           └── fw-test.fw
├── test_compiler_ipt.py                 # iptables expected output tests
└── test_compiler_nft.py                 # nftables expected output tests
```

## How It Works

1. **Fixtures** (`tests/fixtures/*.fwf`, `tests/fixtures/*.fwb`) are firewall databases that exercise specific compiler features. `.fwf` files are hand-crafted YAML; `.fwb` files are XML from the C++ Firewall Builder.
2. **Tests** are auto-discovered from the expected output directory structure. For each `tests/expected-output/<platform>/<fixture_name>/<fw_name>.fw`, a parametrized test case is generated.
3. The test compiles the fixture, passes the output through a **normalize** function (which replaces timestamps, version strings, and iptables chain name hashes with stable placeholders), and compares the result against the expected output file.
4. **Expected output files** are stored in their normalized form, so they are deterministic and diff-friendly.

### Normalization

The `normalize_ipt()` and `normalize_nft()` functions in `tests/normalize.py` replace:

| Pattern | Replacement | Reason |
|---------|-------------|--------|
| `#  Generated <timestamp>` | `#  Generated TIMESTAMP` | Varies per run |
| `#  Firewall Builder  fwb_ipt v<version>` | `#  Firewall Builder  fwb_ipt VERSION` | Varies per release |
| `log "Activating firewall script generated ..."` | `...TIMESTAMP...` | Varies per run |
| `C<hex>.<N>` (iptables chain names) | `CHAIN` | Hash-based, varies per run |
| Trailing whitespace | Stripped | Irrelevant noise |

## Adding Tests for a New Feature

### 1. Create a fixture

Create a new `.fwf` file in `tests/fixtures/`. Name it after the feature being tested (e.g., `nat_snat_dnat.fwf`).

A fixture is a standard FirewallFabrik YAML database.

### 2. Generate expected output files

```bash
python tests/update_expected_output.py --fixture nat_snat_dnat
```

This compiles the fixture with both iptables and nftables, normalizes the output, and saves it under `tests/expected-output/{ipt,nft}/nat_snat_dnat/fw-test.fw`.

### 3. Review the expected output

Manually inspect the generated expected output files to verify the compiler output is correct. This is the most important step — expected output files encode what "correct" means.

### 4. Commit

Commit the fixture and expected output files together. From now on, any change to the compiler that alters the output for this feature will cause the test to fail.

### 5. Verify

```bash
pytest --verbose
```

## Updating Expected Output Files

When you intentionally change compiler output (e.g., fixing a bug, adding a feature), recompile and update the expected output files:

```bash
# Recompile all expected output files from fixtures
python tests/update_expected_output.py

# Recompile only one fixture
python tests/update_expected_output.py --fixture basic_accept_deny

# Recompile only one platform
python tests/update_expected_output.py --platform nft

# Combine both
python tests/update_expected_output.py --fixture basic_accept_deny --platform ipt
```

Always review the diff (`git diff tests/expected-output/`) before committing to confirm the changes are intentional.

## Normalizing Existing Expected Output Files

If you have pre-existing `.fw` files (e.g., from the C++ Firewall Builder compiler or a manual compilation run) that you want to use as expected output files, you can import and normalize them:

1. Copy the files into the appropriate expected output directory:

    ```bash
    mkdir --parents tests/expected-output/ipt/my_feature/
    cp /path/to/reference/fw-test.fw tests/expected-output/ipt/my_feature/
    ```

2. Run `--normalize-only` to normalize them in-place:

    ```bash
    # Normalize all expected output files across both platforms
    python tests/update_expected_output.py --normalize-only

    # Normalize only a specific fixture
    python tests/update_expected_output.py --normalize-only --fixture my_feature

    # Normalize only a specific platform
    python tests/update_expected_output.py --normalize-only --platform ipt
    ```

This applies the same normalization (timestamp/version/chain-hash replacement, trailing whitespace stripping) that the test runner applies to compiler output, so the comparison will match.

The script reports which files were modified and skips files that are already normalized.

## C++ Firewall Builder Regression Suite

### Background

The C++ Firewall Builder project (`fwbuilder`) includes comprehensive iptables regression test suites with expected `.fw` output. These test suites were developed over many years and cover a wide range of iptables features.

We imported these test suites to serve as a **compatibility target** for the Python reimplementation. The expected output files represent the C++ compiler's output and define the behavior we aim to match.

Three C++ reference fixtures are currently imported:

| Fixture | Expected Output Files |
|---|---|
| `objects-for-regression-tests` | 105 |
| `cluster-tests` | 18 |
| `optimizer-test` | 2 |

### What It Covers

The firewalls in `objects-for-regression-tests.fwb` exercise:

- **Basic policy rules**: accept, deny, reject with various combinations of source, destination, service
- **NAT**: SNAT, DNAT, masquerade, redirect, port translation
- **IPv6**: dual-stack firewalls with ip6tables rules, neighbor discovery
- **Services**: TCP, UDP, ICMP, custom protocols, port ranges, multiport
- **Addresses**: single hosts, networks, address ranges, address tables, DNS names
- **Interfaces**: multiple interfaces, dynamic addresses, unnumbered interfaces, bridge/bond interfaces
- **Rule options**: logging, classification/tagging, routing marks, connection marking
- **Advanced features**: custom chains, rule branching, shadowing detection, multiple rule sets, prolog/epilog script insertion points
- **Platform variants**: different iptables versions (1.2.5, 1.2.6, 1.3.x, 1.4.x), IPCop, kernel versions

### Current Status

All C++ reference tests (across all three fixtures) are marked `xfail` because the Python compiler does not yet produce identical output.

As the Python compiler is improved, individual tests will start passing. pytest reports these as `XPASS` (unexpected pass), signaling that the `xfail` marker can be removed and the test promoted to a proper passing test.

### How to Track Progress

```bash
# Run all C++ reference regression tests
pytest --verbose -k "objects-for-regression-tests or cluster-tests or optimizer-test"

# See which tests unexpectedly pass (if any)
pytest --verbose -k "objects-for-regression-tests or cluster-tests or optimizer-test" 2>&1 | grep XPASS
```

### WARNING: Do Not Modify the iptables Expected Output for `.fwb` Fixtures

> **The iptables expected output files for `objects-for-regression-tests`, `cluster-tests`, and `optimizer-test` were compiled with the old, known-good C++ `fwb_ipt` compiler and must not be modified or regenerated.**

These files are the **ground truth** for the Python iptables compiler. They define the correct behavior we are reimplementing. If you regenerate them with `update_expected_output.py`, you will overwrite the C++ reference with Python compiler output, which defeats the entire purpose of these regression tests.

**Do:**
- Use these files as-is to validate the Python compiler against the C++ reference.
- Regenerate expected output only for **`.fwf` fixtures** (e.g., `compiler-tests`, `basic_accept_deny`, `reject_actions`), whose expected output is produced by the Python compiler.
- Regenerate **nftables** expected output and carefully review the changes — there is no C++ nftables reference compiler.

**Do not:**
- Run `update_expected_output.py --platform ipt` on `.fwb` fixtures.
- Manually edit the iptables `.fw` files under `expected-output/ipt/objects-for-regression-tests/`, `expected-output/ipt/cluster-tests/`, or `expected-output/ipt/optimizer-test/`.
- Re-normalize these files (they are already normalized).

## Limitation: Compiler Aborts Cannot Be Tested

The expected output regression framework calls `pytest.fail()` whenever the compiler produces errors (see `_compile()` in `conftest.py`). This means **compiler aborts cannot be tested** with the current framework — there is no way to assert that a specific firewall configuration *should* cause the compiler to abort.

This affects options whose primary behavior is to abort compilation on invalid input:

| Option | Abort behavior | Testable path |
|--------|---------------|---------------|
| `firewall_is_part_of_any_and_networks` | No abort — changes rule splitting | Yes: produces extra INPUT/OUTPUT chain rules |
| `local_nat` | No abort — adds NAT processors | Yes: produces OUTPUT chain NAT rules |
| `ignore_empty_groups` | `false`: aborts on empty groups | Only `true`: removes empty groups with warnings, produces output |
| `check_shading` | `true`: aborts on shadowed rules | Only `false`: no shadowing check, passes through |

When writing test firewalls for these options, **only test the non-abort code paths** that produce output. Abort-path testing would require a separate test mechanism (e.g., a `compile_expect_error` fixture or standalone tests that call the driver directly and assert on `driver.all_errors`).

## Note on nftables Expected Output

Unlike the iptables expected output for `objects-for-regression-tests` (which comes from the C++ Firewall Builder compiler and serves as a verified reference), the **nftables expected output files are generated by our own Python compiler**. There is no independent C++ nftables compiler to validate against.

This means the nft expected output files are **regression tests only** — they capture the current compiler behavior, not necessarily the correct behavior. If the nftables compiler has a bug at the time the expected output is generated, that bug is baked into the expected output.

When reviewing nft expected output files (especially newly created ones), pay extra attention to correctness. The expected output encodes "what the compiler currently produces", not "what is known to be correct".

## Investigating Failures

When an expected output test fails, the assertion message shows both file paths:

```
AssertionError: iptables output differs from expected output.
  Actual:   /tmp/pytest-xxx/test_.../fw-test.fw
  Expected: tests/expected-output/ipt/basic_accept_deny/fw-test.fw
Run "python tests/update_expected_output.py --fixture basic_accept_deny --platform ipt" to update.
```

To investigate:

```bash
# Diff the actual vs expected output
diff --unified tests/expected-output/ipt/basic_accept_deny/fw-test.fw /tmp/pytest-xxx/test_.../fw-test.fw
```

If the change is intentional, update the expected output file. If not, fix the regression.
