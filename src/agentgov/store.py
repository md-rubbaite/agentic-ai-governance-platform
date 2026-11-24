"""SQLite persistence with versioned migrations and a hash-chained audit log.

SQLite keeps the reference deployment to a single file and zero external services. The
store is the only module that touches SQL, so swapping in PostgreSQL is a contained change
(see docs/adr/0002-sqlite-first.md).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from .models import (
    Agent,
    AgentStatus,
    Approval,
    ApprovalStatus,
    Autonomy,
    DataClass,
    Decision,
    DecisionStatus,
    Effect,
    Principal,
    RiskAssessment,
    Role,
)

GENESIS = "0" * 64

MIGRATIONS: list[str] = [
    # 1: initial schema
    """
    CREATE TABLE principals (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE, agent_id TEXT, active INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE agents (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, purpose TEXT NOT NULL,
        autonomy TEXT NOT NULL, allowed_tools TEXT NOT NULL, daily_action_limit INTEGER NOT NULL,
        daily_spend_limit REAL NOT NULL, eu_ai_act_risk TEXT NOT NULL, status TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE policies (
        version TEXT PRIMARY KEY, sha256 TEXT NOT NULL, source TEXT NOT NULL,
        created_at TEXT NOT NULL, created_by TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE decisions (
        id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, tool TEXT NOT NULL, action TEXT NOT NULL,
        effect TEXT NOT NULL, status TEXT NOT NULL, reasons TEXT NOT NULL, risk TEXT NOT NULL,
        policy_version TEXT NOT NULL, matched_rule TEXT, approval_id TEXT, created_at TEXT NOT NULL,
        data_classification TEXT NOT NULL, amount REAL, flags TEXT NOT NULL, arguments_redacted TEXT NOT NULL
    );
    CREATE INDEX ix_decisions_agent ON decisions(agent_id, created_at);
    CREATE TABLE approvals (
        id TEXT PRIMARY KEY, decision_id TEXT NOT NULL UNIQUE, agent_id TEXT NOT NULL,
        required_role TEXT NOT NULL, required_approvals INTEGER NOT NULL, status TEXT NOT NULL,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, votes TEXT NOT NULL
    );
    CREATE INDEX ix_approvals_status ON approvals(status);
    CREATE TABLE usage (
        agent_id TEXT NOT NULL, day TEXT NOT NULL, actions INTEGER NOT NULL, spend REAL NOT NULL,
        PRIMARY KEY (agent_id, day)
    );
    CREATE TABLE audit (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
        event TEXT NOT NULL, subject TEXT NOT NULL, data TEXT NOT NULL,
        prev_hash TEXT NOT NULL, hash TEXT NOT NULL
    );
    """,
]


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(prev_hash: str, ts: str, actor: str, event: str, subject: str, data: dict[str, Any]) -> str:
    payload = _canonical({"prev": prev_hash, "ts": ts, "actor": actor, "event": event, "subject": subject, "data": data})
    return hashlib.sha256(payload.encode()).hexdigest()


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.RLock()
        self._migrate()

    # ---- infrastructure -------------------------------------------------------------
    def _migrate(self) -> None:
        with self._lock:
            current = self._conn.execute("PRAGMA user_version").fetchone()[0]
            for i, script in enumerate(MIGRATIONS[current:], start=current + 1):
                self._conn.executescript("BEGIN;" + script + f"PRAGMA user_version = {i}; COMMIT;")

    @property
    def schema_version(self) -> int:
        return self._conn.execute("PRAGMA user_version").fetchone()[0]

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def ping(self) -> bool:
        return self._conn.execute("SELECT 1").fetchone()[0] == 1

    # ---- principals -----------------------------------------------------------------
    def add_principal(self, p: Principal) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO principals VALUES (?,?,?,?,?,?)",
                (p.id, p.name, p.role.value, p.key_hash, p.agent_id, int(p.active)),
            )

    def principal_by_key_hash(self, key_hash: str) -> Principal | None:
        row = self._conn.execute("SELECT * FROM principals WHERE key_hash = ?", (key_hash,)).fetchone()
        return _principal(row) if row else None

    def get_principal(self, pid: str) -> Principal | None:
        row = self._conn.execute("SELECT * FROM principals WHERE id = ?", (pid,)).fetchone()
        return _principal(row) if row else None

    def list_principals(self) -> list[Principal]:
        return [_principal(r) for r in self._conn.execute("SELECT * FROM principals ORDER BY id")]

    # ---- agents ---------------------------------------------------------------------
    def add_agent(self, a: Agent) -> None:
        with self.transaction() as c:
            c.execute(
                "INSERT INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    a.id,
                    a.name,
                    a.owner,
                    a.purpose,
                    a.autonomy.value,
                    json.dumps(a.allowed_tools),
                    a.daily_action_limit,
                    a.daily_spend_limit,
                    a.eu_ai_act_risk,
                    a.status.value,
                    a.created_at,
                ),
            )

    def get_agent(self, agent_id: str) -> Agent | None:
        row = self._conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        return _agent(row) if row else None

    def list_agents(self) -> list[Agent]:
        return [_agent(r) for r in self._conn.execute("SELECT * FROM agents ORDER BY id")]

    def set_agent_status(self, agent_id: str, status: AgentStatus) -> None:
        with self.transaction() as c:
            c.execute("UPDATE agents SET status = ? WHERE id = ?", (status.value, agent_id))

    # ---- policies -------------------------------------------------------------------
    def save_policy(self, version: str, sha256: str, source: str, created_at: str, created_by: str) -> None:
        with self.transaction() as c:
            if c.execute("SELECT 1 FROM policies WHERE version = ?", (version,)).fetchone():
                raise ValueError(f"policy version '{version}' already exists; bump the version")
            c.execute("UPDATE policies SET active = 0")
            c.execute(
                "INSERT INTO policies VALUES (?,?,?,?,?,1)",
                (version, sha256, source, created_at, created_by),
            )

    def active_policy_source(self) -> str | None:
        row = self._conn.execute("SELECT source FROM policies WHERE active = 1").fetchone()
        return row["source"] if row else None

    def policy_history(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT version, sha256, created_at, created_by, active FROM policies ORDER BY created_at")
        return [dict(r) | {"active": bool(r["active"])} for r in rows]

    # ---- decisions & approvals ------------------------------------------------------
    def save_decision(self, d: Decision, conn: sqlite3.Connection | None = None) -> None:
        sql = "INSERT OR REPLACE INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        args = (
            d.id,
            d.agent_id,
            d.tool,
            d.action,
            d.effect.value,
            d.status.value,
            json.dumps(d.reasons),
            _canonical({"score": d.risk.score, "tier": d.risk.tier, "factors": d.risk.factors}),
            d.policy_version,
            d.matched_rule,
            d.approval_id,
            d.created_at,
            d.data_classification.value,
            d.amount,
            json.dumps(sorted(d.flags)),
            _canonical(d.arguments_redacted),
        )
        if conn is not None:
            conn.execute(sql, args)
        else:
            with self.transaction() as c:
                c.execute(sql, args)

    def get_decision(self, decision_id: str) -> Decision | None:
        row = self._conn.execute("SELECT * FROM decisions WHERE id = ?", (decision_id,)).fetchone()
        return _decision(row) if row else None

    def list_decisions(self, agent_id: str | None = None, limit: int = 50) -> list[Decision]:
        if agent_id:
            rows = self._conn.execute("SELECT * FROM decisions WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?", (agent_id, limit))
        else:
            rows = self._conn.execute("SELECT * FROM decisions ORDER BY created_at DESC LIMIT ?", (limit,))
        return [_decision(r) for r in rows]

    def save_approval(self, a: Approval, conn: sqlite3.Connection | None = None) -> None:
        sql = "INSERT OR REPLACE INTO approvals VALUES (?,?,?,?,?,?,?,?,?)"
        args = (
            a.id,
            a.decision_id,
            a.agent_id,
            a.required_role.value,
            a.required_approvals,
            a.status.value,
            a.created_at,
            a.expires_at,
            json.dumps(a.votes),
        )
        if conn is not None:
            conn.execute(sql, args)
        else:
            with self.transaction() as c:
                c.execute(sql, args)

    def get_approval(self, approval_id: str) -> Approval | None:
        row = self._conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        return _approval(row) if row else None

    def list_approvals(self, status: str | None = None) -> list[Approval]:
        if status:
            rows = self._conn.execute("SELECT * FROM approvals WHERE status = ? ORDER BY created_at", (status,))
        else:
            rows = self._conn.execute("SELECT * FROM approvals ORDER BY created_at DESC")
        return [_approval(r) for r in rows]

    # ---- usage ----------------------------------------------------------------------
    def usage(self, agent_id: str, day: str) -> tuple[int, float]:
        row = self._conn.execute("SELECT actions, spend FROM usage WHERE agent_id = ? AND day = ?", (agent_id, day)).fetchone()
        return (row["actions"], row["spend"]) if row else (0, 0.0)

    def add_usage(self, agent_id: str, day: str, amount: float, conn: sqlite3.Connection) -> None:
        conn.execute(
            "INSERT INTO usage VALUES (?,?,1,?) ON CONFLICT(agent_id, day) "
            "DO UPDATE SET actions = actions + 1, spend = spend + excluded.spend",
            (agent_id, day, amount),
        )

    # ---- audit ----------------------------------------------------------------------
    def append_audit(
        self, ts: str, actor: str, event: str, subject: str, data: dict[str, Any], conn: sqlite3.Connection | None = None
    ) -> str:
        def _append(c: sqlite3.Connection) -> str:
            row = c.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            h = entry_hash(prev, ts, actor, event, subject, data)
            c.execute(
                "INSERT INTO audit (ts, actor, event, subject, data, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (ts, actor, event, subject, _canonical(data), prev, h),
            )
            return h

        if conn is not None:
            return _append(conn)
        with self.transaction() as c:
            return _append(c)

    def audit_entries(self, subject: str | None = None, limit: int = 100, after_seq: int = 0) -> list[dict[str, Any]]:
        if subject:
            rows = self._conn.execute("SELECT * FROM audit WHERE subject = ? AND seq > ? ORDER BY seq LIMIT ?", (subject, after_seq, limit))
        else:
            rows = self._conn.execute("SELECT * FROM audit WHERE seq > ? ORDER BY seq LIMIT ?", (after_seq, limit))
        return [dict(r) | {"data": json.loads(r["data"])} for r in rows]

    def verify_audit(self) -> dict[str, Any]:
        prev = GENESIS
        count = 0
        for r in self._conn.execute("SELECT * FROM audit ORDER BY seq"):
            data = json.loads(r["data"])
            expected = entry_hash(prev, r["ts"], r["actor"], r["event"], r["subject"], data)
            if r["prev_hash"] != prev or r["hash"] != expected:
                return {"valid": False, "entries": count, "first_invalid_seq": r["seq"]}
            prev = r["hash"]
            count += 1
        return {"valid": True, "entries": count, "first_invalid_seq": None, "head": prev}

    def counts(self) -> dict[str, Any]:
        effects = {r["effect"]: r["n"] for r in self._conn.execute("SELECT effect, COUNT(*) n FROM decisions GROUP BY effect")}
        pending = self._conn.execute("SELECT COUNT(*) FROM approvals WHERE status = 'pending'").fetchone()[0]
        audit = self._conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        suspended = self._conn.execute("SELECT COUNT(*) FROM agents WHERE status = 'suspended'").fetchone()[0]
        agents = self._conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
        return {
            "decisions": effects,
            "approvals_pending": pending,
            "audit_entries": audit,
            "agents": agents,
            "agents_suspended": suspended,
        }


def _principal(r: sqlite3.Row) -> Principal:
    return Principal(
        id=r["id"], name=r["name"], role=Role(r["role"]), key_hash=r["key_hash"], agent_id=r["agent_id"], active=bool(r["active"])
    )


def _agent(r: sqlite3.Row) -> Agent:
    return Agent(
        id=r["id"],
        name=r["name"],
        owner=r["owner"],
        purpose=r["purpose"],
        autonomy=Autonomy(r["autonomy"]),
        allowed_tools=json.loads(r["allowed_tools"]),
        daily_action_limit=r["daily_action_limit"],
        daily_spend_limit=r["daily_spend_limit"],
        eu_ai_act_risk=r["eu_ai_act_risk"],
        status=AgentStatus(r["status"]),
        created_at=r["created_at"],
    )


def _decision(r: sqlite3.Row) -> Decision:
    risk = json.loads(r["risk"])
    return Decision(
        id=r["id"],
        agent_id=r["agent_id"],
        tool=r["tool"],
        action=r["action"],
        effect=Effect(r["effect"]),
        status=DecisionStatus(r["status"]),
        reasons=json.loads(r["reasons"]),
        risk=RiskAssessment(score=risk["score"], tier=risk["tier"], factors=risk["factors"]),
        policy_version=r["policy_version"],
        matched_rule=r["matched_rule"],
        approval_id=r["approval_id"],
        created_at=r["created_at"],
        data_classification=DataClass(r["data_classification"]),
        amount=r["amount"],
        flags=json.loads(r["flags"]),
        arguments_redacted=json.loads(r["arguments_redacted"]),
    )


def _approval(r: sqlite3.Row) -> Approval:
    return Approval(
        id=r["id"],
        decision_id=r["decision_id"],
        agent_id=r["agent_id"],
        required_role=Role(r["required_role"]),
        required_approvals=r["required_approvals"],
        status=ApprovalStatus(r["status"]),
        created_at=r["created_at"],
        expires_at=r["expires_at"],
        votes=json.loads(r["votes"]),
    )
