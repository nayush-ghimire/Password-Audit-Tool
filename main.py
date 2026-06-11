import pwinput
import getpass
import pyfiglet

from auditor.patterns  import detect_patterns
from auditor.strength  import estimate_crack_time
from auditor.hibp      import check_password
from auditor.report    import print_strength_report, print_breach_report, print_verdict


def main() -> None:
    print("\033[2J\033[H", end="")
    _GAP = "═" * 80
    print(_GAP)
    print(pyfiglet.figlet_format("Password Audit Tool",font="small"))
    print(_GAP)

    password = pwinput.pwinput(prompt=" Enter password to audit: ", mask="*")

    if not password:
        print("\n  No password entered. Exiting.")
        input("\nPress Enter to exit...")
        return


    pattern_penalty, pattern_weaknesses = detect_patterns(password)


    strength = estimate_crack_time(
        password,
        extra_penalty=pattern_penalty,
        extra_weaknesses=pattern_weaknesses,
    )
    print_strength_report(strength)


    breach_count = 0
    try:
        breach_count = check_password(password)
        print_breach_report(breach_count)
    except Exception as e:
        print(f"\n  [!] HIBP check failed: {e}")
        print(f"      Check your internet connection and try again.")

    print_verdict(strength["score"], breach_count)
    input("\nPress Enter to exit...")


if __name__ == "__main__":
    main()