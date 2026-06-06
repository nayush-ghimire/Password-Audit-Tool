#  Password Audit Tool

> A modular, privacy-focused password strength and vulnerability analyzer built in Python.

![Status](https://img.shields.io/badge/Status-In%20Development-orange?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge)



## Features

- Entropy-based password strength analysis
- Character set diversity evaluation
- Pattern detection (keyboard walks, common words, leetspeak)
- Password breach check using HaveIBeenPwned (k-anonymity model)
- Clear CLI-based security report

---

##  Structure

| File | Purpose |
|------|--------|
| `main.py` | Entry point  |
| `auditor/strength.py` | Entropy and strength calculations |
| `auditor/patterns.py` | Pattern and dictionary detection |
| `auditor/hibp.py` | Breach check via HaveIBeenPwned API |
| `auditor/report.py` | Formats final output report |
| `tests/` | Unit tests for modules |
| `wordlists/` | Optional wordlists for weak password detection |

---

## How this tool works ?

1. User enters a password via CLI
2. Strength is analyzed using entropy + character diversity
3. Patterns are checked (dictionary words, keyboard patterns, leetspeak)
4. SHA-1 hash prefix is sent to HIBP API (k-anonymity)
5. Final report is generated

---

## Installation

```bash
git clone https://github.com/nayush-ghimire/password-audit-tool.git
cd password-audit-tool
pip install requests pytest
```
## ⚠️ Disclaimer



This tool is designed to analyze passwords locally and does not transmit plaintext passwords over the network.
However, no security tool can guarantee complete protection against software bugs, system compromise, or implementation errors.

**Please avoid testing with sensitive passwords.**