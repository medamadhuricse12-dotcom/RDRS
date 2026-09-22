from app.core.detector import (
    calculate_threat_score,
    severity_from_score,
    analyze_window_result,
)


def test_threat_score_calculation():
    score = calculate_threat_score(
        rapid_encryption=True,
        mass_rename=True,
        high_entropy=True,
    )

    assert score == 95


def test_threat_score_never_exceeds_100():
    score = calculate_threat_score(
        rapid_encryption=True,
        mass_rename=True,
        high_entropy=True,
        cpu_spike=True,
        unknown_program=True,
    )

    assert score == 100


def test_severity_normal():
    assert severity_from_score(0) == "Normal"


def test_severity_warning():
    assert severity_from_score(50) == "Warning"


def test_severity_critical():
    assert severity_from_score(80) == "Critical"


def test_window_detection():
    result = analyze_window_result(
        {
            "modified_files": 10,
            "renamed_files": 5,
            "high_entropy_files": 1,
        }
    )

    assert result["threat_score"] == 95
    assert result["severity"] == "Critical"
    assert result["rapid_encryption"] is True
    assert result["mass_rename"] is True
    assert result["high_entropy"] is True
