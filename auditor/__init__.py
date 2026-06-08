from hibp import check_password
from strength import estimate_crack_time, SCORE_LABELS


SCORE_ICONS = {0: "✗✗✗", 1: "✗✗", 2: "✗", 3: "✓", 4: "✓✓"}


def print_strength_report(result: dict) -> None:
    score = result["score"]
    label = SCORE_LABELS[score]
    icon = SCORE_ICONS[score]

    print(f"\n{'─'*45}")
    print(f"  STRENGTH ANALYSIS")
    print(f"{'─'*45}")
    print(f"  Rating      : {icon}  {label}")
    print(f"  Entropy     : {result['entropy_bits']} bits")
    print(f"  Charset     : {result['charset_size']} possible characters")
    print(f"  Length      : {result['length']} characters")
    print(f"  Crack time  : {result['human']}  (brute force, GPU cluster)")

    if result["weaknesses"]:
        print(f"\n  ⚠  Weaknesses detected:")
        for w in result["weaknesses"]:
            print(f"       - {w}")

    print(f"{'─'*45}")


def print_breach_report(count: int) -> None:
    print(f"\n{'─'*45}")
    print(f"  BREACH CHECK  (Have I Been Pwned)")
    print(f"{'─'*45}")

    if count:
        print(f"  ✗  Found {count:,} times in known data breaches.")
        print(f"  This password is in attacker wordlists.")
        print(f"  Change it immediately on all accounts.")
        print(f"  → https://haveibeenpwned.com/Passwords")
    else:
        print(f"  ✓  Not found in any known breach database.")
        print(f"  Note: absence here doesn't guarantee safety.")

    print(f"{'─'*45}")


def main():
    print("\n  Password Audit Tool")
    print("  ═══════════════════\n")

    password = input("  Enter password to audit: ")

    if not password:
        print("\n  No password entered. Exiting.")
        return

    # --- Strength analysis (always runs, no network needed) ---
    strength = estimate_crack_time(password)
    print_strength_report(strength)

    # --- HIBP breach check ---
    try:
        count = check_password(password)
        print_breach_report(count)
    except Exception as e:
        print(f"\n  [!] HIBP check failed: {e}")
        print(f"      Check your internet connection and try again.")

    # --- Overall verdict ---
    print(f"\n  VERDICT")
    score = strength["score"]
    breach_hit = False

    try:
        breach_hit = count > 0
    except NameError:
        pass

    if breach_hit:
        print(f"  ✗  UNSAFE — password is in breach databases. Change it now.\n")
    elif score <= 1:
        print(f"  ✗  UNSAFE — password is too weak. Use a longer, random password.\n")
    elif score == 2:
        print(f"  ⚠  MARGINAL — consider a stronger password.\n")
    else:
        print(f"  ✓  LOOKS GOOD — strong password, not found in breaches.\n")


if __name__ == "__main__":
    main()