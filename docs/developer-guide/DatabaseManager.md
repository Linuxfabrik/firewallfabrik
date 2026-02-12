# DatabaseManager

The `firewallfabrik.core.DatabaseManager` class manages the in-memory SQLAlchemy database that holds all firewall objects, rules, and configuration data.

## `session()` — Managed Session (Recommended)

`dm.session()` is a context manager that wraps an SQLAlchemy session in a transaction. The session is automatically committed when the context manager exits. Additionally, the current database state is pushed onto the undo stack if any data changes occurred.

```python
with dm.session() as session:
    fw = session.query(Firewall).filter_by(name="fw1").one()
    fw.comment = "Updated comment"
# Transaction is committed and undo state is saved automatically
```

Use `session()` for all normal operations — it handles commit and undo tracking for you.

## `create_session()` — Manual Session

`create_session()` returns a new SQLAlchemy session without automatic commit or undo tracking. You must manually commit the session and, if needed, create an undo save state via `save_state()`.

```python
session = dm.create_session()
fw = session.query(Firewall).filter_by(name="fw1").one()
fw.comment = "Updated comment"
session.commit()
dm.save_state()  # manually push to undo stack if needed
```

Use `create_session()` only when you need fine-grained control over transaction boundaries or want to avoid undo stack entries (e.g. during initial file loading).
