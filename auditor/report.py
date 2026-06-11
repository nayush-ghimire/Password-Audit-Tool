from auditor.strength import SCORE_LABELS


SCORE_ICONS = {
    0: "✗✗✗",
    1: "✗✗",
    2: "✗",
    3: "✓",
    4: "✓✓",
}

_LINE = "─" * 80


def print_strength_report(result: dict) -> None:

    score = result["score"]
    label = SCORE_LABELS[score]
    icon  = SCORE_ICONS[score]

    print(f"\n{_LINE}")
    print(f"  STRENGTH ANALYSIS")
    print(_LINE)
    print(f"  Rating      : {icon}  {label}")
    print(f"  Entropy     : {result['entropy_bits']} bits")
    print(f"  Charset     : {result['charset_size']} possible characters")
    print(f"  Length      : {result['length']} characters")
    print(f"  Crack time  : {result['human']}  (brute force, GPU cluster)")
    print(f"  Wordlist    : {result['wordlist_msg']}")  # New confirmation line

    if result["weaknesses"]:
        print(f"\n  ⚠  Weaknesses detected:")
        for w in result["weaknesses"]:
            print(f"       - {w}")

    print(_LINE)


def print_breach_report(count: int) -> None:
    """Prints the HIBP breach check section."""
    print(f"\n{_LINE}")
    print(f"  BREACH CHECK  (Have I Been Pwned)")
    print(_LINE)

    if count:
        print(f"  ✗  Found {count:,} times in known data breaches.")
        print(f"  This password is in attacker wordlists.")
        print(f"  Change it immediately on all accounts.")
        print(f"  → https://haveibeenpwned.com/Passwords")
    else:
        print(f"  ✓  Not found in any known breach database.")
        print(f"  Note: absence here does not guarantee safety.")

    print(_LINE)


def print_verdict(score: int, breach_count: int) -> None:
    """Prints the final overall verdict."""
    print(f"\n  VERDICT")

    if breach_count > 0:
        print(f"  ✗  UNSAFE — found in breach databases. Change it now.\n")
    elif score <= 1:
        print(f"  ✗  UNSAFE — too weak. Use a longer, random password.\n")
    elif score == 2:
        print(f"  ⚠  MARGINAL — consider a stronger password.\n")
    else:
        print(f"  ✓  LOOKS GOOD — strong and not found in breaches.\n")