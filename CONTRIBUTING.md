# Contributing

## Pre-commit

This project uses [pre-commit](https://pre-commit.com/) to run linting, formatting, and license header checks automatically before each commit.

Install `pre-commit <https://pre-commit.com/#install>`_, then configure the hooks once after cloning:
```bash
pre-commit install
```

## Interacting with the In-Memory Database

- firewallfabrik.core.DatabaseManager's session() vs create_session()
  - session(): a contextmanager that wraps an SQLAlchemy session for the database. This session runs in a transaction and is automatically committed once the contextmanager exits. Additionally, the current database state is pushed onto the undo stack if any data changes occurred.
  - create_session(): Returns a new 'manual' SQLAlchemy session. This session needs to be manually committed and, if needed, a undo stack save state needs to be created using save_state()
