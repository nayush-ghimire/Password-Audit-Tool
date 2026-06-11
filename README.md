# Password Audit Tool

> A modular, privacy-focused password strength and vulnerability analyser built in Python.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-GNU%20GPL%20v3.0-red?style=for-the-badge)

---

## Features

- **Entropy-based strength scoring** — Calculates charset size and entropy bits, then estimates crack time against a simulated 100 billion hashes/second GPU cluster
- **Pattern detection** — Flags keyboard walks (`qwerty`, `asdfgh`, etc.), repeated characters, sequential runs (`abcde`, `12345`), and leet-speak disguises of common passwords
- **10,000-entry wordlist check** — Tests the password against a local common-passwords database; no network request needed for this step
- **HaveIBeenPwned breach check** — Uses the k-anonymity API: only the first 5 characters of the SHA-1 hash are sent, the plaintext password never leaves your machine
- **Scored verdict** — Combines the strength score and breach count into a clear final verdict: `UNSAFE`, `MARGINAL`, or `LOOKS GOOD`

---

## How It Works

1. You enter a password at the CLI prompt
2. Patterns are detected (keyboard walks, repeated/sequential chars, leet-speak)
3. The detected patterns apply a cumulative penalty multiplier to the entropy-based crack time estimate
4. The password is checked against the local 10,000-entry wordlist (adds a 1,000,000× penalty if matched)
5. The first 5 characters of the SHA-1 hash are sent to the HIBP Pwned Passwords API; the response is checked locally for the full hash suffix
6. A structured report is printed — strength analysis, breach result, and a final verdict

---

## Score Ratings

| Score | Label       | Crack Time Threshold             |
|-------|-------------|----------------------------------|
| 0     | Very Weak   | Under 1 second, or under 6 chars |
| 1     | Weak        | Under 1 hour, or entropy < 28 bits |
| 2     | Fair        | Under 1 month, or entropy < 40 bits |
| 3     | Strong      | Under 10 years                   |
| 4     | Very Strong | 10 years or more                 |

---

## Project Structure

| Path                          | Purpose                                                        |
|-------------------------------|----------------------------------------------------------------|
| `main.py`                     | Entry point — orchestrates all modules                         |
| `auditor/strength.py`         | Charset analysis, entropy calculation, crack time estimation, wordlist check, score calculation |
| `auditor/patterns.py`         | Keyboard walk, repeated char, sequential char, and leet-speak detection |
| `auditor/hibp.py`             | k-anonymity SHA-1 prefix lookup via HaveIBeenPwned API         |
| `auditor/report.py`           | Formats and prints the strength report, breach report, and verdict |
| `wordlists/common_passwords.txt` | 10,000-entry common password list used for local wordlist checks |

---

## Installation

```bash
git clone https://github.com/nayush-ghimire/Password-Audit-Tool.git
cd Password-Audit-Tool
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

Example output:

```
═════════════════════
  Password Audit Tool
═════════════════════

  Enter password to audit: ••••••••

─────────────────────────────────────────────
  STRENGTH ANALYSIS
─────────────────────────────────────────────
  Rating      : ✓✓  Very Strong
  Entropy     : 65.6 bits
  Charset     : 94 possible characters
  Length      : 10 characters
  Crack time  : millions of years  (brute force, GPU cluster)
  Wordlist    : ✓  Not found in local wordlist database.
─────────────────────────────────────────────

─────────────────────────────────────────────
  BREACH CHECK  (Have I Been Pwned)
─────────────────────────────────────────────
  ✓  Not found in any known breach database.
  Note: absence here does not guarantee safety.
─────────────────────────────────────────────

  VERDICT
  ✓  LOOKS GOOD — strong and not found in breaches.
```

---

## Privacy

- The plaintext password is **never transmitted** over the network
- The HIBP check sends only the first 5 characters of the SHA-1 hash (k-anonymity model); the full hash is matched locally
- All wordlist checks are performed entirely offline

---

## Requirements

- Python 3.10+
- [`requests`](https://pypi.org/project/requests/)
- [`pytest`](https://docs.pytest.org/)

---

## ⚠️ Disclaimer

This tool is intended for auditing passwords you own or are authorised to test. No security tool can guarantee protection against all attack vectors. **Do not test passwords you actively use in production.**
