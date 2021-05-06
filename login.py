from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import bcrypt_check
from getpass import getpass
import usermgmt
import sys

usermgmt.user = sys.argv[1]
hash_map = usermgmt.hash_map
forcepass = usermgmt.forcepass
usermgmt.open_files()

while True:
    try:
        password = getpass("Password: ")
        # Pre-hashing
        pwd = SHA256.new(password.encode()).digest().hex()
        # Checking hash
        bcrypt_check(pwd, bytes.fromhex(hash_map[usermgmt.user]))
        # Checking forcepass
        if usermgmt.user in forcepass:
            usermgmt.password = getpass("New password: ")

            while len(usermgmt.password) < 8 or len(usermgmt.password) > 64 or usermgmt.password == password or \
                    not (any(map(str.islower, usermgmt.password)) and any(map(str.isupper, usermgmt.password)) and
                         any(map(str.isdigit, usermgmt.password))):
                if usermgmt.password == password:
                    print("New password must be different from old password.")
                elif not any(map(str.islower, usermgmt.password)):
                    print("Your password must contain at least one lowercase letter.")
                elif not any(map(str.isupper, usermgmt.password)):
                    print("Your password must contain at least one uppercase letter.")
                elif not any(map(str.isdigit, usermgmt.password)):
                    print("Your password must contain at least one number digit.")
                else:
                    print("Invalid password length. (8 <= password <= 64)")
                usermgmt.password = getpass("New password: ")

            if usermgmt.password != getpass("Repeat new password: "):
                print("Password change failed. Password mismatch.")
                continue
            else:
                usermgmt.save_password()

            forcepass.remove(usermgmt.user)
            usermgmt.save_files()
        print("Login successful.")
        exit(0)
    except (KeyError, ValueError):
        print("Username or password incorrect.")
