from __future__ import annotations

from agentgov.store import GENESIS, Store, entry_hash


def test_migrations_are_idempotent(tmp_path):
    db = str(tmp_path / "g.db")
    s1 = Store(db)
    assert s1.schema_version == 1
    s1.append_audit("2026-11-24T09:00:00+00:00", "x", "e", "s", {"a": 1})
    s2 = Store(db)  # reopening must not re-run migrations or lose data
    assert s2.schema_version == 1
    assert s2.verify_audit()["entries"] == 1


def test_audit_chain_links_and_verifies():
    s = Store()
    h1 = s.append_audit("t1", "alice", "e1", "s1", {"k": "v"})
    h2 = s.append_audit("t2", "bob", "e2", "s2", {"n": 2})
    assert h1 == entry_hash(GENESIS, "t1", "alice", "e1", "s1", {"k": "v"})
    assert h2 == entry_hash(h1, "t2", "bob", "e2", "s2", {"n": 2})
    result = s.verify_audit()
    assert result == {"valid": True, "entries": 2, "first_invalid_seq": None, "head": h2}


def test_tampering_is_detected_at_the_edited_entry():
    s = Store()
    for i in range(5):
        s.append_audit(f"t{i}", "a", "e", "s", {"i": i})
    s._conn.execute("UPDATE audit SET data = '{\"i\":99}' WHERE seq = 3")
    assert s.verify_audit() == {"valid": False, "entries": 2, "first_invalid_seq": 3}


def test_deleting_an_entry_breaks_the_chain():
    s = Store()
    for i in range(4):
        s.append_audit(f"t{i}", "a", "e", "s", {"i": i})
    s._conn.execute("DELETE FROM audit WHERE seq = 2")
    assert s.verify_audit()["first_invalid_seq"] == 3


def test_audit_filtering_and_paging():
    s = Store()
    for i in range(6):
        s.append_audit(f"t{i}", "a", "e", "even" if i % 2 == 0 else "odd", {"i": i})
    assert [e["data"]["i"] for e in s.audit_entries("even")] == [0, 2, 4]
    assert [e["seq"] for e in s.audit_entries(None, limit=2, after_seq=3)] == [4, 5]
