import math
from collections import Counter


def calculate_entropy(file_path: str, sample_size: int = 64 * 1024) -> float:
    """Calculate Shannon entropy (0-8) from the first 64 KB of a file."""
    try:
        with open(file_path, "rb") as file:
            data = file.read(sample_size)

        if not data:
            return 0.0

        counts = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    except (OSError, IOError):
        return 0.0
