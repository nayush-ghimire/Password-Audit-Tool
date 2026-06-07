import hashlib
import requests


def check_password(password: str) -> int:
    """
    Returns the number of times the password
    appears in the HIBP database.
    """

    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()

    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        timeout=10
    )

    response.raise_for_status()

    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0