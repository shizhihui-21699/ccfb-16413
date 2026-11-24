"""Durable, low-trust state used to catch invitation *updates*.

Stateless content checks cannot see the thing attackers exploit most: the
relationship between this message and the last one.  A CANCEL for a meeting you
never received, an update whose SEQUENCE goes backwards, or a REQUEST that
reuses a known UID from a different organizer are all invisible without memory.

The store is deliberately boring: one JSON file, atomic replace, bounded size,
and every failure degraded to "no memory" rather than "no protection".
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCHEMA_VERSION = 1
MAX_RECORDS = 200_000


@dataclass
class UidRecord:
    uid: str
    organizer: str = ""
    sender: str = ""
    sequence: int | None = None
    dtstamp: str = ""
    method: str = ""
    summary_fingerprint: str = ""
    link_hosts: list[str] = field(default_factory=list)
    recurrence_ids: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    seen_count: int = 0
    decision: str = ""

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class DomainReputation:
    domain: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    invites: int = 0
    approved: int = 0
    held: int = 0
    blocked: int = 0
    organiser_names: list[str] = field(default_factory=list)

    @property
    def is_known(self) -> bool:
        return self.approved > 0 and self.blocked == 0

    @property
    def is_bad(self) -> bool:
        return self.blocked >= 2 and self.blocked > self.approved


@dataclass
class TrustStore:
    """JSON-backed memory.

    ``allow_domains`` is administrative (the org's known customer/partner
    domains).  ``uids`` and ``domains`` are learned.  All three matter, and all
    three are advisory: nothing here can whitelist a hard content signal.
    """

    path: Path | None = None
    allow_domains: set[str] = field(default_factory=set)
    uids: dict[str, UidRecord] = field(default_factory=dict)
    domains: dict[str, DomainReputation] = field(default_factory=dict)
    dirty: bool = False

    # -- lifecycle --------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path | None) -> "TrustStore":
        store = cls(path=Path(path) if path else None)
        if store.path is None or not store.path.exists():
            return store
        try:
            raw = json.loads(store.path.read_text("utf-8"))
        except (OSError, ValueError):
            # Corrupt or unreadable state must never stop mail flow.
            return store
        if not isinstance(raw, dict) or raw.get("schema") != SCHEMA_VERSION:
            return store
        store.allow_domains = {str(d).lower() for d in raw.get("allow_domains", [])}
        for uid, rec in (raw.get("uids") or {}).items():
            try:
                store.uids[uid] = UidRecord(**rec)
            except TypeError:
                continue
        for domain, rec in (raw.get("domains") or {}).items():
            try:
                store.domains[domain] = DomainReputation(**rec)
            except TypeError:
                continue
        return store

    def save(self, *, force: bool = False) -> None:
        if self.path is None or (not self.dirty and not force):
            return
        payload = {
            "schema": SCHEMA_VERSION,
            "saved_at": time.time(),
            "allow_domains": sorted(self.allow_domains),
            "uids": {k: v.to_json() for k, v in self.uids.items()},
            "domains": {k: asdict(v) for k, v in self.domains.items()},
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".trust-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        self.dirty = False

    # -- queries ----------------------------------------------------------
    def uid(self, uid: str) -> UidRecord | None:
        return self.uids.get(uid) if uid else None

    def domain(self, domain: str) -> DomainReputation | None:
        return self.domains.get(domain) if domain else None

    def is_allowed_domain(self, domain: str) -> bool:
        return domain.lower() in self.allow_domains

    # -- updates ----------------------------------------------------------
    def remember_uid(self, record: UidRecord, *, decision: str = "") -> None:
        record.last_seen = time.time()
        if not record.first_seen:
            record.first_seen = record.last_seen
        record.seen_count += 1
        if decision:
            record.decision = decision
        if len(self.uids) >= MAX_RECORDS and record.uid not in self.uids:
            self._evict()
        self.uids[record.uid] = record
        self.dirty = True

    def observe_domain(
        self,
        domain: str,
        *,
        decision: str,
        organizer_name: str = "",
        now: float | None = None,
    ) -> DomainReputation:
        if not domain:
            return DomainReputation(domain="")
        stamp = time.time() if now is None else now
        rep = self.domains.get(domain)
        if rep is None:
            rep = DomainReputation(domain=domain, first_seen=stamp)
            self.domains[domain] = rep
        rep.last_seen = stamp
        rep.invites += 1
        if decision == "allow":
            rep.approved += 1
        elif decision in {"pending", "hold"}:
            rep.held += 1
        elif decision in {"quarantine", "block", "reject"}:
            rep.blocked += 1
        if organizer_name and organizer_name not in rep.organiser_names and len(rep.organiser_names) < 8:
            rep.organiser_names.append(organizer_name)
        self.dirty = True
        return rep

    def _evict(self) -> None:
        """Drop the least-recently-seen 10% of records."""
        keep = int(MAX_RECORDS * 0.9)
        ordered = sorted(self.uids.items(), key=lambda kv: kv[1].last_seen, reverse=True)
        self.uids = dict(ordered[:keep])

    def prune(self, *, older_than_days: float = 400.0, now: float | None = None) -> int:
        stamp = time.time() if now is None else now
        cutoff = stamp - older_than_days * 86_400
        before = len(self.uids)
        self.uids = {k: v for k, v in self.uids.items() if v.last_seen >= cutoff}
        removed = before - len(self.uids)
        if removed:
            self.dirty = True
        return removed
