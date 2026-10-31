"""CVSS v3.1 base score calculation — spec: "strictly follow OWASP CVSS v3.1".

Reference: FIRST CVSS v3.1 specification (cvss.mitre.org), section 8.1.
"""

import pytest

from app.core.cvss import CvssVector, calculate_base_score, severity_from_score


class TestCvssVectorParsing:
    def test_parses_full_vector_into_components(self):
        vec = CvssVector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert vec.attack_vector == "N"
        assert vec.attack_complexity == "L"
        assert vec.privileges_required == "N"
        assert vec.user_interaction == "N"
        assert vec.scope == "U"
        assert vec.confidentiality == "H"
        assert vec.integrity == "H"
        assert vec.availability == "H"

    def test_rejects_unknown_metric(self):
        with pytest.raises(ValueError):
            CvssVector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:X")

    def test_rejects_wrong_version_prefix(self):
        with pytest.raises(ValueError):
            CvssVector.parse("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")

    def test_rejects_missing_metric(self):
        with pytest.raises(ValueError):
            CvssVector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")

    def test_round_trips_to_canonical_string(self):
        raw = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert CvssVector.parse(raw).to_string() == raw


class TestBaseScore:
    @pytest.mark.parametrize(
        "vector,expected",
        [
            # Critical: network, no auth, no user interaction, full CIA impact.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            # Critical: auth required, scope changed.
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
            # Medium: network, high complexity, low confidentiality only.
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),
            # Low: local, high complexity, privileges required, user interaction.
            ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
            # None: no impact.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
            # Scope changed with low CIA impact.
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
            # High: NVD reference example, network + high complexity.
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L", 7.7),
        ],
    )
    def test_known_vectors_score_correctly(self, vector, expected):
        assert calculate_base_score(vector) == expected

    def test_scores_are_clamped_to_ten(self):
        assert calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0

    def test_vector_instance_is_accepted_directly(self):
        vec = CvssVector.parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert calculate_base_score(vec) == 9.8


class TestSeverityRating:
    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.0, "NONE"),
            (0.1, "LOW"),
            (3.9, "LOW"),
            (4.0, "MEDIUM"),
            (6.9, "MEDIUM"),
            (7.0, "HIGH"),
            (8.9, "HIGH"),
            (9.0, "CRITICAL"),
            (10.0, "CRITICAL"),
        ],
    )
    def test_severity_bands(self, score, expected):
        assert severity_from_score(score) == expected
