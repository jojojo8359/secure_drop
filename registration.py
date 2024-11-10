import json
from getpass import getpass
from contacts import users_file

# Right now, it is assumed that the users file does not exist if a user is going
# to be registered - just create the file now
def register_user():
    print("")
    while True:
        name: str = input("Enter Full Name: ").strip()
        if name != "":
            break
        print("Please enter a name.")
    while True:
        email: str = input("Enter Email Address: ").strip()
        if email != "":
            break
        print("Please enter an email.")

    password1: str = "a"
    password2: str = "b"
    while password1 != password2 or password1 == "":
        password1 = getpass("Enter Password: ")
        password2 = getpass("Re-enter Password: ")
        if password1 != password2:
            print("Passwords don't match, try again.")
        elif password1 == "":
            print("Please enter a password.")
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
