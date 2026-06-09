

import hashlib
import requests


def check_password(password: str) -> int:
    
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        timeout=10,
    )
    response.raise_for_status()

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0