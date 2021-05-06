from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.KDF import bcrypt
import sys


# Creates empty files for saving data
def create_files():
    file = open("hash.txt", "w")
    file.close()

    file = open("forcepass.txt", "w")
    file.close()


# Opens files and stores its content to lists
def open_files():
    with open("hash.txt", "r") as file:
        for line in file:
            hash_map[line.split(' ')[0]] = line.split(' ')[1].strip()

    with open("forcepass.txt", "r") as file:
        for username in file:
            forcepass.add(username.strip())


# Saves updated data from lists to files
def save_files():
    file = open("hash.txt", "w")
    for key in hash_map:
        file.write(key + ' ' + hash_map[key] + '\n')
    file.close()

    file = open("forcepass.txt", "w")
    for username in forcepass:
        file.write(username + '\n')
    file.close()


# Adds new user and password or changes current password
def save_password():
    # Pre-hashing
    pwd = SHA256.new(password.encode()).digest().hex()
    # Hashing
    bcrypt_hash = bcrypt(pwd, 12)
    # Appending hash to list
    hash_map[user] = bcrypt_hash.hex()


# Inputs complex password
def input_password():
    result = input("Password: ")

    while len(result) < 8 or len(result) > 64 or \
            not (any(map(str.islower, result)) and any(map(str.isupper, result)) and any(map(str.isdigit, result))):
        if not any(map(str.islower, result)):
            print("Your password must contain at least one lowercase letter.")
        elif not any(map(str.isupper, result)):
            print("Your password must contain at least one uppercase letter.")
        elif not any(map(str.isdigit, result)):
            print("Your password must contain at least one number digit.")
        else:
            print("Invalid password length. (8 <= password <= 64)")
        result = input("Password: ")

    return result


hash_map = {}
forcepass = set()

if __name__ == '__main__':
    if sys.argv[1] == 'init':
        create_files()
        print("Password authenticator initialized.")
        exit(0)

    open_files()
    user = sys.argv[2]

    if sys.argv[1] == 'add':
        if user in hash_map.keys():
            print("User add failed. User " + user + " already added.")
            exit(0)

        password = input_password()

        if password != input("Repeat Password: "):
            print("User add failed. Password mismatch.")
        else:
            save_password()
            print("User " + user + " successfully added.")

    elif user not in hash_map.keys():
        print("User " + user + " not added.")

    elif sys.argv[1] == 'passwd':
        password = input_password()

        if password != input("Repeat Password: "):
            print("Password change failed. Password mismatch.")
        else:
            save_password()
            print("Password change successful.")

    elif sys.argv[1] == 'forcepass':
        if user in forcepass:
            print("Request already sent.")
        else:
            forcepass.add(user)
            print("User will be requested to change password on next login.")

    elif sys.argv[1] == 'del':
        hash_map.pop(user)
        forcepass.discard(user)
        print("User successfully removed.")

    else:
        print("Command doesn't exist.")

    save_files()
