import string
import math


# Common passwords / patterns that are weak regardless of length
COMMON_PASSWORDS = {
    "password", "123456", "password1", "qwerty", "abc123",
    "letmein", "monkey", "master", "dragon", "sunshine",
    "princess", "welcome", "shadow", "superman", "michael",
}

KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
    "12345", "123456", "1234567", "12345678", "123456789",
    "password", "iloveyou",
]


def calculate_charset_size(password: str) -> int:
    """Returns the number of possible characters based on what's used."""
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += 32
    return size or 1


def detect_penalties(password: str) -> tuple[float, list[str]]:
    """
    Returns a penalty multiplier (>= 1.0) and list of weakness reasons.
    Higher penalty = weaker password.
    """
    penalty = 1.0
    reasons = []

    lower = password.lower()

    # Check common passwords
    if lower in COMMON_PASSWORDS:
        penalty *= 1_000_000
        reasons.append("extremely common password")

    # Check keyboard walks
    for walk in KEYBOARD_WALKS:
        if walk in lower:
            penalty *= 10_000
            reasons.append("keyboard pattern detected")
            break

    # Repeated characters (e.g. "aaaa", "1111")
    if len(set(password)) <= 2:
        penalty *= 1_000
        reasons.append("too many repeated characters")
    elif len(set(password)) <= len(password) // 3:
        penalty *= 10
        reasons.append("low character variety")

    # Sequential characters (e.g. "abcd", "1234")
    sequential_count = sum(
        1 for i in range(len(password) - 2)
        if ord(password[i+1]) - ord(password[i]) == 1
        and ord(password[i+2]) - ord(password[i+1]) == 1
    )
    if sequential_count >= 3:
        penalty *= 100
        reasons.append("sequential characters detected")

    return penalty, reasons


def estimate_crack_time(password: str) -> dict:
    """
    Estimates the time to crack a password via brute force.

    Returns a dict with:
        - seconds (float): raw estimated seconds
        - human (str): human-readable time string e.g. "3 years"
        - entropy_bits (float): password entropy
        - charset_size (int): effective character set size
        - score (int): 0-4 strength score
        - weaknesses (list[str]): detected weaknesses
    """
    # Attacker speed: modern GPU cluster (~100 billion hashes/sec for SHA1)
    HASHES_PER_SECOND = 100_000_000_000

    charset_size = calculate_charset_size(password)
    length = len(password)

    # Entropy = log2(charset^length)
    entropy_bits = length * math.log2(charset_size) if charset_size > 1 else 0

    # Brute force: on average need to try half the keyspace
    total_combinations = charset_size ** length
    base_seconds = (total_combinations / 2) / HASHES_PER_SECOND

    # Apply penalties for patterns
    penalty, weaknesses = detect_penalties(password)
    adjusted_seconds = base_seconds / penalty

    human = _seconds_to_human(adjusted_seconds)

    # Score 0-4
    score = _calculate_score(adjusted_seconds, length, entropy_bits)

    return {
        "seconds": adjusted_seconds,
        "human": human,
        "entropy_bits": round(entropy_bits, 1),
        "charset_size": charset_size,
        "length": length,
        "score": score,
        "weaknesses": weaknesses,
    }


def _seconds_to_human(seconds: float) -> str:
    """Converts seconds to the most meaningful human-readable unit."""
    if seconds < 0.001:
        return "instantly"
    if seconds < 1:
        return f"{seconds * 1000:.0f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3_600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86_400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 86_400 * 30:
        return f"{seconds / 86400:.1f} days"
    if seconds < 86_400 * 365:
        return f"{seconds / (86400 * 30):.1f} months"
    if seconds < 86_400 * 365 * 1_000:
        years = seconds / (86_400 * 365)
        return f"{years:,.0f} year{'s' if years >= 2 else ''}"
    if seconds < 86_400 * 365 * 1_000_000:
        return f"{seconds / (86400 * 365 * 1000):,.0f} thousand years"
    return "millions of years"


def _calculate_score(seconds: float, length: int, entropy: float) -> int:
    """
    Strength score 0-4:
        0 = Very Weak
        1 = Weak
        2 = Fair
        3 = Strong
        4 = Very Strong
    """
    if seconds < 1 or length < 6:
        return 0
    if seconds < 3600 or entropy < 28:        # under 1 hour
        return 1
    if seconds < 86_400 * 30 or entropy < 40: # under 1 month
        return 2
    if seconds < 86_400 * 365 * 10:           # under 10 years
        return 3
    return 4


SCORE_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong",
}