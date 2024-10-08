import json
import os
import sys
from getpass import getpass

users_file: str = "users.json"

# Right now, it is assumed that the users file does not exist if a user is going
# to be registered - just create the file now
def register_user():
    print("")
    name: str = input("Enter Full Name: ").strip()
    email: str = input("Enter Email Address: ").strip()
    password1: str = "a"
    password2: str = "b"
    while password1 != password2:
        password1 = getpass("Enter Password: ")
        password2 = getpass("Re-enter Password: ")
        if password1 != password2:
            print("Passwords don't match, try again.")
    print("\nPasswords match.")
    user_obj: dict[str, str] = {"name": name, "email": email,
                                "password": password1}
    with open(users_file, 'w') as f:
        json.dump([user_obj], f)
    print("User registered.")

def login():
    signed_in: bool = False
    while not signed_in:
        email: str = input("Enter Email Address: ").strip()
        password: str = getpass("Enter Password: ")
        with open(users_file, 'r') as f:
            users = json.load(f)
            for user in users:
                if email == user["email"] and password == user["password"]:
                    print(user["name"] +
                          ": Username and Password verified. Welcome.")
                    signed_in = True
                    break
        if not signed_in:
            print("Couldn't sign in, try again.")

if __name__ == "__main__":
    if not os.path.exists(users_file):
        # ask if the user wants to register a new user
        print("No users are registered with this client.")
        confirmation: str = ""
        while confirmation != "y" and confirmation != "n":
            confirmation = input("Do you want to register a new user (y/n)? "
                                 ).strip().lower()
        if confirmation == "y":
            register_user()
        elif confirmation == "n":
            # quit program
            print("Goodbye!")
            sys.exit(0)
        else:
            print("You shouldn't be here - goodbye!")
            sys.exit(1)
    else:
        login()
