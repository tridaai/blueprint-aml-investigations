"""Transaction and rule-pack feeds: the core-banking side of the ports.

The typology engine (Law 4) reads stored transaction records, and
the records arrive through these feeds. The reference feed's streams
are gold-by-construction: they actually contain the patterns the
seed alerts describe (the structuring deposits the structuring alert
names by id, the dormant account's same-day in-and-out, the velocity
burst) and clean controls that must produce no findings at all.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import AccountProfile, RulePack, Transaction


class ListTransactionFeed:
    """TransactionSource over in-memory streams (tests, embedding)."""

    def __init__(
        self,
        profiles: list[AccountProfile],
        streams: dict[str, list[Transaction]],
    ) -> None:
        self._profiles = {p.account_id: p for p in profiles}
        self._streams = {account: list(txns) for account, txns in streams.items()}

    def list_account_ids(self) -> list[str]:
        return sorted(self._streams)

    def get_profile(self, account_id: str) -> AccountProfile | None:
        return self._profiles.get(account_id)

    def get_transactions(self, account_id: str) -> list[Transaction]:
        return list(self._streams.get(account_id, []))


class ReferenceTransactionFeed:
    """TransactionSource over a JSON file of profiles + streams."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._profiles: dict[str, AccountProfile] = {}
        self._streams: dict[str, list[Transaction]] = {}
        if self._path.exists():
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            for entry in payload.get("profiles", []):
                profile = AccountProfile.model_validate(entry)
                self._profiles[profile.account_id] = profile
            for account_id, entries in payload.get("transactions", {}).items():
                self._streams[account_id] = [
                    Transaction.model_validate(entry) for entry in entries
                ]

    def list_account_ids(self) -> list[str]:
        return sorted(self._streams)

    def get_profile(self, account_id: str) -> AccountProfile | None:
        return self._profiles.get(account_id)

    def get_transactions(self, account_id: str) -> list[Transaction]:
        return list(self._streams.get(account_id, []))


class ListRulePackFeed:
    """RulePackSource over an in-memory list (tests, embedding)."""

    def __init__(self, packs: list[RulePack]) -> None:
        self._packs = list(packs)

    def list_rule_packs(self) -> list[RulePack]:
        return list(self._packs)


class ReferenceRulePackFeed:
    """RulePackSource over a JSON file of rule-pack definitions."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._packs: list[RulePack] = []
        if self._path.exists():
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            for entry in payload.get("packs", []):
                self._packs.append(RulePack.model_validate(entry))

    def list_rule_packs(self) -> list[RulePack]:
        return list(self._packs)
