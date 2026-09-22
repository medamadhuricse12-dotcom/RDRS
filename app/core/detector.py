from pathlib import Path

from app.core.entropy import calculate_entropy


def calculate_threat_score(
    rapid_encryption=False,
    mass_rename=False,
    high_entropy=False,
    cpu_spike=False,
    unknown_program=False,
):
    score = 0

    if rapid_encryption:
        score += 40

    if mass_rename:
        score += 30

    if high_entropy:
        score += 25

    if cpu_spike:
        score += 15

    if unknown_program:
        score += 10

    return min(score, 100)


def severity_from_score(score):
    if score < 40:
        return "Normal"

    if score < 70:
        return "Warning"

    return "Critical"


def analyze_file(
    file_path,
    rapid_encryption=False,
    mass_rename=False,
    cpu_spike=False,
    unknown_program=False,
):
    path = Path(file_path)

    entropy = calculate_entropy(str(path))

    high_entropy = entropy >= 7.0

    score = calculate_threat_score(
        rapid_encryption=rapid_encryption,
        mass_rename=mass_rename,
        high_entropy=high_entropy,
        cpu_spike=cpu_spike,
        unknown_program=unknown_program,
    )

    return {
        "file_path": str(path),
        "entropy": entropy,
        "high_entropy": high_entropy,
        "threat_score": score,
        "severity": severity_from_score(score),
    }


def analyze_window_result(window_result):
    modified_files = window_result["modified_files"]
    renamed_files = window_result["renamed_files"]
    high_entropy_files = window_result["high_entropy_files"]

    rapid_encryption = modified_files >= 10
    mass_rename = renamed_files >= 5
    high_entropy = high_entropy_files > 0

    score = calculate_threat_score(
        rapid_encryption=rapid_encryption,
        mass_rename=mass_rename,
        high_entropy=high_entropy,
    )

    return {
        "threat_score": score,
        "severity": severity_from_score(score),
        "rapid_encryption": rapid_encryption,
        "mass_rename": mass_rename,
        "high_entropy": high_entropy,
    }
