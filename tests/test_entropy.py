from app.core.entropy import calculate_entropy


def test_entropy_returns_float():
    entropy = calculate_entropy("requirements.txt")

    assert isinstance(entropy, float)


def test_entropy_is_non_negative():
    entropy = calculate_entropy("requirements.txt")

    assert entropy >= 0
