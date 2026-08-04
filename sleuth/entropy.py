"""Shannon entropy calculation for high-entropy secret detection."""

from __future__ import annotations

import math
from collections import Counter
from typing import Optional


def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy (closer to 8.0 for bytes) indicates more randomness,
    which is characteristic of secrets, keys, and tokens.
    """
    if not data:
        return 0.0

    # Use character frequency
    frequency = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_high_entropy(
    data: str,
    threshold: float = 4.5,
    min_length: int = 16,
    max_length: int = 256,
) -> bool:
    """
    Determine if a string has high entropy and is likely a secret.

    Args:
        data: The candidate string
        threshold: Minimum entropy score (typical secrets are > 4.0-5.0)
        min_length: Ignore very short strings
        max_length: Ignore extremely long strings (performance + false positives)

    Returns:
        True if the string is considered high-entropy
    """
    if not data or len(data) < min_length or len(data) > max_length:
        return False

    # Quick filters to reduce false positives
    if data.isdigit() or data.isalpha():
        # Pure numbers or pure letters are rarely high-entropy secrets
        return False

    # Prefer mixed alphanumeric + special chars
    has_digit = any(c.isdigit() for c in data)
    has_alpha = any(c.isalpha() for c in data)
    if not (has_digit and has_alpha):
        return False

    entropy = shannon_entropy(data)
    return entropy >= threshold


def extract_high_entropy_strings(
    text: str,
    threshold: float = 4.5,
    min_length: int = 20,
    max_length: int = 128,
) -> list[tuple[str, float, int]]:
    """
    Extract candidate high-entropy strings from text.

    Returns list of (string, entropy_score, start_offset)
    """
    import re

    # Match potential secrets: sequences of base64-ish / hex-ish / token-ish chars
    # This is a broad regex to catch candidates before entropy filtering
    pattern = re.compile(
        r"""(?x)
        (?:
            # Base64-like (common for tokens)
            [A-Za-z0-9+/]{20,}={0,2}
            |
            # Hex strings
            [A-Fa-f0-9]{32,}
            |
            # General high-entropy tokens (letters + digits + some symbols)
            [A-Za-z0-9_\-]{20,}
        )
        """
    )

    results: list[tuple[str, float, int]] = []
    seen = set()

    for match in pattern.finditer(text):
        candidate = match.group(0)
        if candidate in seen:
            continue
        seen.add(candidate)

        if is_high_entropy(candidate, threshold, min_length, max_length):
            score = shannon_entropy(candidate)
            results.append((candidate, score, match.start()))

    return results
