from auditor.strength import COMMON_PASSWORDS

# Reference data

KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop",
    "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm",
    "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "password", "iloveyou",
    "qweasd", "qweasdzxc",
]

# Leet-speak substitution map  (symbol → plain letter)
LEET_MAP = {
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "5": "s", "$": "s",
    "7": "t",
    "+": "t",
    "8": "b",
    "6": "g",
}


# Individual checks

def _check_keyboard_walk(password: str) -> tuple[float, list[str]]:
    lower = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in lower:
            return 10_000.0, ["keyboard walk pattern detected"]
    return 1.0, []


def _check_repeated_chars(password: str) -> tuple[float, list[str]]:
    unique = len(set(password))
    total = len(password)
    if unique <= 2:
        return 1_000.0, ["almost all characters are the same"]
    if total >= 6 and unique <= total // 3:
        return 10.0, ["low character variety (many repeats)"]
    return 1.0, []


def _check_sequential_chars(password: str) -> tuple[float, list[str]]:
    sequential_runs = sum(
        1 for i in range(len(password) - 2)
        if ord(password[i + 1]) - ord(password[i]) == 1
        and ord(password[i + 2]) - ord(password[i + 1]) == 1
    )
    if sequential_runs >= 3:
        return 100.0, ["long sequential character run (e.g. abcde / 12345)"]
    return 1.0, []


def _check_leet_speak(password: str) -> tuple[float, list[str]]:
   
    de_leeted = "".join(LEET_MAP.get(c, c) for c in password.lower())
    if de_leeted != password.lower() and de_leeted in COMMON_PASSWORDS:
        return 500.0, [f"leet-speak disguise of common password: '{de_leeted}'"]
    return 1.0, []


# Public API

def detect_patterns(password: str) -> tuple[float, list[str]]:
    
    total_penalty = 1.0
    all_reasons: list[str] = []

    for check in (
        _check_keyboard_walk,
        _check_repeated_chars,
        _check_sequential_chars,
        _check_leet_speak,
    ):
        penalty, reasons = check(password)
        total_penalty *= penalty
        all_reasons.extend(reasons)

    return total_penalty, all_reasons