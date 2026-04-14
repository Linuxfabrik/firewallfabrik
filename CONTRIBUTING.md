# Contributing


## Linuxfabrik Standards

The following standards apply to all Linuxfabrik repositories.


### Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).


### Issue Tracking

Open issues are tracked on GitHub Issues in the respective repository.


### Pre-commit

Some repositories use [pre-commit](https://pre-commit.com/) for automated linting and formatting checks. If the repository contains a `.pre-commit-config.yaml`, install [pre-commit](https://pre-commit.com/#install) and configure the hooks after cloning:

```bash
pre-commit install
```


### Commit Messages

Commit messages follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification:

```
<type>(<scope>): <subject>
```

If there is a related issue, append `(fix #N)`:

```
<type>(<scope>): <subject> (fix #N)
```

`<type>` must be one of:

- `chore`: Changes to the build process or auxiliary tools and libraries
- `docs`: Documentation only changes
- `feat`: A new feature
- `fix`: A bug fix
- `perf`: A code change that improves performance
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `style`: Changes that do not affect the meaning of the code (whitespace, formatting, etc.)
- `test`: Adding missing tests


### Changelog

Document all changes in `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Sort entries within sections alphabetically.


### Language

Code, comments, commit messages, and documentation must be written in English.


### CI Supply Chain

GitHub Actions in `.github/workflows/` are pinned by commit SHA, not by tag. Dependabot's `github-actions` ecosystem keeps these pins up to date.

Python packages installed via `pip` inside workflows follow a two-tier policy:

- `pre-commit` is installed from a hash-pinned requirements file at `.github/pre-commit/requirements.txt`, generated with `pip-compile --generate-hashes --strip-extras` from `.github/pre-commit/requirements.in`. Dependabot's `pip` ecosystem watches that directory and maintains both files.
- One-shot installs such as `ansible-builder`, `build`, `mkdocs`, `pdoc`, and `ruff` in release, docs, or test workflows are version-pinned only (`package==X.Y.Z`) and kept fresh by Dependabot. Scorecard's `pipCommand not pinned by hash` findings for these are considered acceptable risk and may be dismissed.


### Coding Conventions

- Sort variables, parameters, lists, and similar items alphabetically where possible.
- Always use long parameters when using shell commands.
- Use RFC [5737](https://datatracker.ietf.org/doc/html/rfc5737), [3849](https://datatracker.ietf.org/doc/html/rfc3849), [7042](https://datatracker.ietf.org/doc/html/rfc7042#section-2.1.1), and [2606](https://datatracker.ietf.org/doc/html/rfc2606) in examples and documentation:
    - IPv4: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
    - IPv6: `2001:DB8::/32`
    - MAC: `00-00-5E-00-53-00` through `00-00-5E-00-53-FF` (unicast), `01-00-5E-90-10-00` through `01-00-5E-90-10-FF` (multicast)
    - Domains: `*.example`, `example.com`


---


## FirewallFabrik Guidelines


### Commit Scopes

Common scopes for this project:

- `feat(gui):` -- new GUI feature
- `fix(gui):` -- GUI bug fix
- `fix(compiler):` -- compiler bug fix
- `docs:` -- documentation changes
- `chore:` -- maintenance (dependencies, CI, formatting)
- `refactor:` -- code restructuring without behaviour change


### Static Analysis

The repository runs `bandit` (security) and `vulture` (dead code) as pre-commit hooks. Both are configured in `pyproject.toml` and must pass cleanly before a commit is accepted.

**Acceptance rules:**

- `bandit -c pyproject.toml --severity-level=low --confidence-level=low` runs clean over `src/` **and** `tests/`.
- Every `# nosec` annotation has a short comment explaining why the rule does not apply in that context.
- Globally skipped checks (currently `B110`, `B112`, `B311`) live in `[tool.bandit]` in `pyproject.toml` and require a comment in the same table.
- Test-only relaxations (currently `B101` for pytest-style asserts in `tests/`) live in `[tool.bandit.assert_used]` so that the rest of the rule set still runs over the test tree.

**How to write `# nosec` comments:**

Bandit parses everything after `# nosec` on the same line as a space-separated list of test IDs. Descriptive text on the same line produces `Test in comment: ... is not a test name or id, ignoring` warnings and is silently swallowed. Use this format:

```python
# Short justification on its own comment line above the offending line.
offending_call(...)  # nosec BXXX
```

Never mix the two on one line:

```python
# WRONG — bandit treats "address" and "comparison" as unknown test IDs.
if ip == _ipa.ip_address('0.0.0.0'):  # nosec B104 - address comparison, not bind
```

For multiple rule IDs on one line, separate them with spaces, not commas:

```python
subprocess.run([...], check=True)  # nosec B603 B607
```

**How to run the checks locally:**

```bash
pre-commit run --all-files
```

Or individually:

```bash
pre-commit run bandit --all-files
pre-commit run vulture --all-files
```

When adding a new `nosec` annotation, always run bandit once and grep the output for the `Test in comment:` warning before committing.


### Developer Guide

Detailed developer documentation lives in [`docs/developer-guide/`](docs/developer-guide/):

- [DatabaseManager](docs/developer-guide/DatabaseManager.md)
- [Debugging](docs/developer-guide/Debugging.md)
- [DesignDecisions](docs/developer-guide/DesignDecisions.md)
- [PlatformDefaults](docs/developer-guide/PlatformDefaults.md)
- [RuleProcessors](docs/developer-guide/RuleProcessors.md)
- [Testing](docs/developer-guide/Testing.md)
