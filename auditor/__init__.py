from hibp import check_password

def main():
    password = input("Enter password to audit: ")

    try:
        count = check_password(password)

        if count:
            print(f"\nWARNING\n Password found {count:,} times in breaches.")
            print("\nAny Hacker can try a dictionary attack to crack this password and use it to compromise your accounts. Consider changing it immediately.")
            print("For more information, visit: https://haveibeenpwned.com/Passwords")
        else:
            print("\nPassword not found in HIBP database.")
            print("However, this does not guarantee that the password is secure. Always use strong, unique passwords for each of your accounts.")

    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()