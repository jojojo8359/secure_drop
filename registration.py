import json
from hash import *
from util import get_name, get_email, get_password_register, get_password

USERS_FILE: str = "users.json"


def register_user() -> None:
    """
    Register a new user by prompting for their name, email, and password.
    
    Updates the users file with their encrypted information.
    """
    print("")
    name = get_name()
    email = get_email()

    password = get_password_register()
    # Perform password encryption with salting
    salt = get_salt()
    user_obj: dict[str, str] = {"name": name, "id": id_hash(email),
                                "password": pass_salt_and_hash(password, salt),
                                "salt": salt.hex()}
    # Write output to user JSON file
    with open(USERS_FILE, 'w') as f:
        json.dump([user_obj], f)
    print("User registered.")


def login() -> str:
    """
    Allows a user to log in.
    
    Returns a user's contact hash after they sign in (combination of their email
    and password).
    """
    signed_in: bool = False
    while not signed_in:
        email: str = get_email()
        password: str = get_password()
        # The users file does allow for multiple user profiles to be saved, but
        # currently only one can be saved at a time
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
            for user in users:
                salt = bytes.fromhex(user["salt"])
                if id_hash(email) == user["id"]:
                    if pass_salt_and_hash(password, salt) == user["password"]:
                        print(user["name"] + ": Username and Password verified. Welcome.")
                        signed_in = True
                        contact_hash = SHA512.new(truncate="256")
                        contact_hash.update(bytearray(email, "utf-8"))
                        contact_hash.update(bytearray(password, "utf-8"))
                        email = ""
                        password = ""
                        return contact_hash.hexdigest()
        if not signed_in:
            print("Couldn't sign in, try again.")
