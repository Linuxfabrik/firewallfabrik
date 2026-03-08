# Contributing


## Pre-commit

This project uses [pre-commit](https://pre-commit.com/) to run linting, formatting, and license header checks automatically before each commit.

Install [pre-commit](https://pre-commit.com/#install), then configure the hooks once after cloning:
```bash
pre-commit install
```


## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/). Common scopes:

* `feat(gui):` — new GUI feature
* `fix(gui):` — GUI bug fix
* `fix(compiler):` — compiler bug fix
* `docs:` — documentation changes
* `chore:` — maintenance (dependencies, CI, formatting)
* `refactor:` — code restructuring without behaviour change


## Issue Tracking

Open issues are tracked on [GitHub Issues](https://github.com/Linuxfabrik/firewallfabrik/issues). Code stubs reference the corresponding issue URL in a comment so they are easy to find.


## Developer Guide

Detailed developer documentation lives in [`docs/developer-guide/`](docs/developer-guide/):

* [DatabaseManager](docs/developer-guide/DatabaseManager.md)
* [Debugging](docs/developer-guide/Debugging.md)
* [DesignDecisions](docs/developer-guide/DesignDecisions.md)
* [PlatformDefaults](docs/developer-guide/PlatformDefaults.md)
* [RuleProcessors](docs/developer-guide/RuleProcessors.md)
* [Testing](docs/developer-guide/Testing.md)
