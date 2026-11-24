"""Argument inspection: prompt-injection markers, secrets and personal data.

The guards look at the arguments an agent wants to pass to a tool. They do not decide
anything themselves; they raise flags that feed the risk score and the policy, and they
produce a redacted copy of the arguments for the audit log so that secrets and personal
data are not stored.

Pattern matching is a heuristic layer, not a guarantee. See docs/security/threat-model.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_INJECTION = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
        r"disregard (the |your )?(system|previous) (prompt|instructions)",
        r"you are now (in )?(developer|dan|unrestricted) mode",
        r"reveal (your|the) (system prompt|hidden instructions)",
        r"<\|im_start\|>|<\|system\|>|\[/?INST\]",
        r"\bdo not (tell|inform) the (user|human|reviewer)\b",
        r"\bexfiltrate\b",
    )
]

_SECRETS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "api_key": re.compile(r"\b(sk|rk)-[A-Za-z0-9_-]{20,}\b"),
    "password_assignment": re.compile(r"\b(password|passwd|pwd)\s*[:=]\s*\S{6,}", re.IGNORECASE),
}

# Order matters for redaction: card numbers are replaced before the broader phone pattern.
_PII = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}\b"),
    "card_number": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    # international format only (+country code), to avoid flagging invoice and order numbers
    "phone": re.compile(r"(?<![\w+])\+\d{1,3}[ \-]?(?:\(\d{1,4}\)[ \-]?)?\d{2,4}(?:[ \-]?\d{2,4}){1,4}\b"),
}


@dataclass(slots=True, frozen=True)
class GuardReport:
    flags: frozenset[str]
    findings: tuple[str, ...]
    redacted: dict[str, Any]


def inspect(arguments: dict[str, Any], justification: str = "") -> GuardReport:
    findings: list[str] = []
    flags: set[str] = set()

    for path, text in _strings(arguments, "args"):
        _scan(path, text, flags, findings)
    if justification:
        _scan("justification", justification, flags, findings)

    return GuardReport(frozenset(flags), tuple(findings), _redact(arguments))


def _scan(path: str, text: str, flags: set[str], findings: list[str]) -> None:
    for pattern in _INJECTION:
        if pattern.search(text):
            flags.add("injection")
            findings.append(f"{path}: prompt-injection marker")
            break
    for name, pattern in _SECRETS.items():
        if pattern.search(text):
            flags.add("secret")
            findings.append(f"{path}: {name}")
    for name, pattern in _PII.items():
        match = pattern.search(text)
        if match and (name != "card_number" or _luhn(match.group())):
            flags.add("pii")
            findings.append(f"{path}: {name}")


def _strings(value: Any, path: str):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, f"{path}.{k}")
    elif isinstance(value, list | tuple):
        for i, v in enumerate(value):
            yield from _strings(v, f"{path}[{i}]")


def _redact(value: Any) -> Any:
    if isinstance(value, str):
        out = value
        for name, pattern in _SECRETS.items():
            out = pattern.sub(f"[REDACTED:{name}]", out)
        for name, pattern in _PII.items():
            if name == "card_number":
                out = pattern.sub(lambda m: "[REDACTED:card_number]" if _luhn(m.group()) else m.group(), out)
            else:
                out = pattern.sub(f"[REDACTED:{name}]", out)
        return out
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_redact(v) for v in value]
    return value


def _luhn(candidate: str) -> bool:
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
