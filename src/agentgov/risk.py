"""Transparent, additive risk scoring.

The score is the sum of named factors, capped at 100. Every factor is returned with the
decision so that a reviewer can see why an action scored the way it did. Weights can be
tuned per deployment through the ``[risk]`` table of the policy file, for example::

    [risk.action]
    payment = 30
"""

from __future__ import annotations

from .models import RiskAssessment

DEFAULT_WEIGHTS: dict[str, dict[str, int]] = {
    "action": {
        "read": 5,
        "search": 5,
        "write": 15,
        "external_communication": 15,
        "delete": 25,
        "payment": 25,
        "execute_code": 25,
        "change_permissions": 30,
        "other": 10,
    },
    "data_classification": {"public": 0, "internal": 5, "confidential": 15, "restricted": 25},
    "autonomy": {"assistive": 0, "supervised": 5, "autonomous": 15},
    "eu_ai_act_risk": {"minimal": 0, "limited": 5, "high": 15},
    "flags": {"pii": 10, "injection": 20, "secret": 30},
}

# (upper bound inclusive, weight); amounts above the last bound get the last weight
AMOUNT_BANDS: tuple[tuple[float, int], ...] = ((100, 5), (1_000, 10), (10_000, 20), (float("inf"), 30))

TIERS: tuple[tuple[int, str], ...] = ((24, "low"), (49, "medium"), (74, "high"), (100, "critical"))


def assess(
    *,
    action: str,
    data_classification: str,
    autonomy: str,
    eu_ai_act_risk: str,
    flags: frozenset[str],
    amount: float | None,
    overrides: dict[str, dict[str, int]] | None = None,
) -> RiskAssessment:
    weights = {k: dict(v) for k, v in DEFAULT_WEIGHTS.items()}
    for group, values in (overrides or {}).items():
        weights.setdefault(group, {}).update(values)

    factors: dict[str, int] = {
        "action": weights["action"].get(action, weights["action"]["other"]),
        "data_classification": weights["data_classification"].get(data_classification, 25),
        "autonomy": weights["autonomy"].get(autonomy, 15),
        "eu_ai_act_risk": weights["eu_ai_act_risk"].get(eu_ai_act_risk, 15),
    }
    if amount is not None and amount > 0:
        factors["amount"] = next(w for bound, w in AMOUNT_BANDS if amount <= bound)
    for flag in sorted(flags):
        factors[f"flag:{flag}"] = weights["flags"].get(flag, 10)

    score = min(100, sum(factors.values()))
    tier = next(name for bound, name in TIERS if score <= bound)
    return RiskAssessment(score=score, tier=tier, factors=factors)
