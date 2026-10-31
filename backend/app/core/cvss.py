"""CVSS v3.1 base score engine.

Implements the base score equation from the FIRST CVSS v3.1 specification
(section 8.1) exactly, including the "Roundup" function defined in
Appendix A, so scores match the official calculator.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math
from dataclasses import dataclass

CVSS_VERSION = "3.1"

_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_METRIC_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


@dataclass(frozen=True)
class CvssVector:
    """A parsed and validated CVSS v3.1 base vector."""

    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality: str
    integrity: str
    availability: str

    @classmethod
    def parse(cls, raw: str) -> "CvssVector":
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("CVSS vector must be a non-empty string")
        raw = raw.strip()
        parts = raw.split("/")
        if not parts or parts[0] != f"CVSS:{CVSS_VERSION}":
            raise ValueError(
                f"CVSS vector must start with 'CVSS:{CVSS_VERSION}' (got {parts[0]!r})"
            )
        metrics: dict[str, str] = {}
        for part in parts[1:]:
            if ":" not in part:
                raise ValueError(f"Malformed CVSS metric segment: {part!r}")
            key, _, value = part.partition(":")
            key = key.strip().upper()
            value = value.strip().upper()
            if key not in _REQUIRED_METRICS:
                raise ValueError(f"Unknown CVSS metric: {key}")
            if key in metrics:
                raise ValueError(f"Duplicate CVSS metric: {key}")
            metrics[key] = value

        missing = [m for m in _REQUIRED_METRICS if m not in metrics]
        if missing:
            raise ValueError(f"Missing CVSS metrics: {', '.join(missing)}")

        if metrics["AV"] not in _AV_WEIGHTS:
            raise ValueError(f"Invalid AV value: {metrics['AV']}")
        if metrics["AC"] not in _AC_WEIGHTS:
            raise ValueError(f"Invalid AC value: {metrics['AC']}")
        if metrics["PR"] not in {"N", "L", "H"}:
            raise ValueError(f"Invalid PR value: {metrics['PR']}")
        if metrics["UI"] not in _UI_WEIGHTS:
            raise ValueError(f"Invalid UI value: {metrics['UI']}")
        if metrics["S"] not in {"U", "C"}:
            raise ValueError(f"Invalid S value: {metrics['S']}")
        for impact in ("C", "I", "A"):
            if metrics[impact] not in _CIA_WEIGHTS:
                raise ValueError(f"Invalid {impact} value: {metrics[impact]}")

        return cls(
            attack_vector=metrics["AV"],
            attack_complexity=metrics["AC"],
            privileges_required=metrics["PR"],
            user_interaction=metrics["UI"],
            scope=metrics["S"],
            confidentiality=metrics["C"],
            integrity=metrics["I"],
            availability=metrics["A"],
        )

    def to_string(self) -> str:
        values = {
            "AV": self.attack_vector,
            "AC": self.attack_complexity,
            "PR": self.privileges_required,
            "UI": self.user_interaction,
            "S": self.scope,
            "C": self.confidentiality,
            "I": self.integrity,
            "A": self.availability,
        }
        return "/".join(
            [f"CVSS:{CVSS_VERSION}"]
            + [f"{key}:{values[key]}" for key in _METRIC_ORDER]
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "AV": self.attack_vector,
            "AC": self.attack_complexity,
            "PR": self.privileges_required,
            "UI": self.user_interaction,
            "S": self.scope,
            "C": self.confidentiality,
            "I": self.integrity,
            "A": self.availability,
        }


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup function (Appendix A).

    Smallest number, specified to one decimal place, that is equal to or
    higher than its input.
    """
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def calculate_base_score(vector: "CvssVector | str") -> float:
    """Compute the CVSS v3.1 base score for a vector string or instance."""
    vec = vector if isinstance(vector, CvssVector) else CvssVector.parse(vector)

    scope_changed = vec.scope == "C"
    pr_weights = _PR_WEIGHTS_CHANGED if scope_changed else _PR_WEIGHTS_UNCHANGED

    isc_base = 1 - (
        (1 - _CIA_WEIGHTS[vec.confidentiality])
        * (1 - _CIA_WEIGHTS[vec.integrity])
        * (1 - _CIA_WEIGHTS[vec.availability])
    )

    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    if impact <= 0:
        return 0.0

    exploitability = (
        8.22
        * _AV_WEIGHTS[vec.attack_vector]
        * _AC_WEIGHTS[vec.attack_complexity]
        * pr_weights[vec.privileges_required]
        * _UI_WEIGHTS[vec.user_interaction]
    )

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    return round(_roundup(raw), 1)


def severity_from_score(score: float) -> str:
    """Qualitative severity rating for a CVSS base score."""
    if score <= 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
