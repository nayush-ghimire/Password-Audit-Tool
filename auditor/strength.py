import string
import math
from pathlib import Path

# Load common passwords from wordlist

def _load_common_passwords() -> set[str]:

    wordlist_path = Path(__file__).parent.parent / "wordlists" / "common_passwords.txt"
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return {"password", "123456", "qwerty", "letmein", "admin"}


COMMON_PASSWORDS: set[str] = _load_common_passwords()

# Charset analysis

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


# Common password check using wordlist

def check_common(password: str) -> tuple[bool, float, list[str]]:
    """
    Checks if password is in the common passwords set.
    Returns: (is_common, penalty_multiplier, messages_list)
    """
    if password.lower() in COMMON_PASSWORDS:
        return True, 1_000_000.0, ["extremely common password (found in wordlist)"]
    return False, 1.0, ["✓  Not found in local wordlist database."]


# Crack time estimation

def estimate_crack_time(password: str, extra_penalty: float = 1.0,
                        extra_weaknesses: list[str] | None = None) -> dict:
    
    HASHES_PER_SECOND = 100_000_000_000  # ~100B/s, modern GPU cluster (SHA-1)

    charset_size = calculate_charset_size(password)
    length = len(password)

    entropy_bits = length * math.log2(charset_size) if charset_size > 1 else 0.0

    total_combinations = charset_size ** length
    base_seconds = (total_combinations / 2) / HASHES_PER_SECOND

    # Wordlist penalty (from this module)
    is_common, wordlist_penalty, wordlist_reasons = check_common(password)

    # Pattern penalty (passed in from patterns.py)
    combined_penalty = wordlist_penalty * extra_penalty
    adjusted_seconds = base_seconds / combined_penalty

    # Only treat it as a structural weakness if it was actually found in the list
    all_weaknesses = (wordlist_reasons if is_common else []) + (extra_weaknesses or [])

    return {
        "seconds":      adjusted_seconds,
        "human":        _seconds_to_human(adjusted_seconds),
        "entropy_bits": round(entropy_bits, 1),
        "charset_size": charset_size,
        "length":       length,
        "score":        _calculate_score(adjusted_seconds, length, entropy_bits),
        "weaknesses":   all_weaknesses,
        "wordlist_msg": wordlist_reasons[0],  # Extract the status message string
    }


# Helpers

def _seconds_to_human(seconds: float) -> str:
    """Converts a raw seconds value to the most meaningful human-readable unit."""
    if seconds < 0.001:
        return "instantly"
    if seconds < 1:
        return f"{seconds * 1000:.0f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3_600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86_400:
        return f"{seconds / 3_600:.1f} hours"
    if seconds < 86_400 * 30:
        return f"{seconds / 86_400:.1f} days"
    if seconds < 86_400 * 365:
        return f"{seconds / (86_400 * 30):.1f} months"
    if seconds < 86_400 * 365 * 1_000:
        years = seconds / (86_400 * 365)
        return f"{years:,.0f} year{'s' if years >= 2 else ''}"
    if seconds < 86_400 * 365 * 1_000_000:
        return f"{seconds / (86_400 * 365 * 1_000):,.0f} thousand years"
    return "millions of years"


#Score calculation

def _calculate_score(seconds: float, length: int, entropy: float) -> int:

    if seconds < 1 or length < 6:
        return 0
    if seconds < 3_600 or entropy < 28:          # under 1 hour
        return 1
    if seconds < 86_400 * 30 or entropy < 40:    # under 1 month
        return 2
    if seconds < 86_400 * 365 * 10:              # under 10 years
        return 3
    return 4


SCORE_LABELS = {
    0: "Very Weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very Strong",
}