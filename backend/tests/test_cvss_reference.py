"""Cross-check our CVSS v3.1 engine against the reference `cvss` library.

The `cvss` package is an independent implementation of the FIRST v3.1
specification. If our engine agrees with it across a broad vector sample,
the arithmetic is right.
"""

import pytest

from app.core.cvss import CvssVector, calculate_base_score, severity_from_score

cvss_lib = pytest.importorskip("cvss")

SAMPLE_VECTORS = [
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
    "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
    "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:N/A:N",
    "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L",
    "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N",
]


@pytest.mark.parametrize("vector", SAMPLE_VECTORS)
def test_matches_reference_implementation(vector):
    reference = cvss_lib.CVSS3(vector).scores()[0]
    assert calculate_base_score(vector) == reference


@pytest.mark.parametrize("vector", SAMPLE_VECTORS)
def test_severity_band_matches_reference_rating(vector):
    reference_rating = cvss_lib.CVSS3(vector).severities()[0]
    ours = severity_from_score(calculate_base_score(vector))
    assert ours.lower() == reference_rating.lower()


def test_vector_components_round_trip_through_reference_library():
    vec = CvssVector.parse("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N")
    ref = cvss_lib.CVSS3(vec.to_string())
    metrics = ref.metrics
    assert metrics["AV"] == "A"
    assert metrics["AC"] == "H"
    assert metrics["PR"] == "L"
    assert metrics["UI"] == "R"
    assert metrics["S"] == "C"
