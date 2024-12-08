import json
import os
from filenames import USERS_FILE
from hash import id_hash, get_salt, pass_salt_and_hash, user_contact_hash, encrypt, decrypt
from util import get_name, get_email, get_password_register, get_password, clear_str


class WrongInfo(Exception):
    pass


def register_user() -> None:
    """
    Register a new user by prompting for their name, email, and password.
    
    Updates the users file with their encrypted information.
    """
    print('')

    name: str = get_name()
    email: str = get_email()
    id_: str = id_hash(email)
    password: str = get_password_register()

    # Perform password encryption with salting
    salt: bytes = get_salt()
    contact_hash: str = user_contact_hash(email, password, salt)
    password_hash: str = pass_salt_and_hash(password, salt)

    user_info, tag = encrypt(json.dumps({'name': name, 'id': id_, 'password': password_hash}), contact_hash)

    # Write output to user JSON file
    with open(USERS_FILE, 'w') as f:
        json.dump({'info': tag.hex() + user_info.hex(), 'salt': salt.hex()}, f)
    os.chmod(USERS_FILE, 0o444)  # make file read only

    clear_str(name)
    clear_str(email)
    clear_str(id_)
    clear_str(password)
    clear_str(contact_hash)
    clear_str(password_hash)
    print("User registered.")


def login() -> str:
    """
    Allows a user to log in.
    
    Returns a user's contact hash after they sign in (combination of their email
    and password).
    """
    with open(USERS_FILE, 'r') as f:
        contents: dict[str, str] = json.load(f)
        salt: bytes = bytes.fromhex(contents['salt'])
        info: bytes = bytes.fromhex(contents['info'])
        tag: bytes = info[:16]
        encr_user_info: bytes = info[16:]

    while True:
        email: str = get_email()
        password: str = get_password()
        id_: str = id_hash(email)
        password_hash: str = pass_salt_and_hash(password, salt)
        contact_hash: str = user_contact_hash(email, password, salt)

        try:
            user_info = json.loads(decrypt(encr_user_info, tag, contact_hash))
            if id_ != user_info['id'] or password_hash != user_info['password']:
                raise WrongInfo
        except Exception:
            # if given wrong email and password json decoder will fail
            clear_str(email)
            clear_str(password)
            clear_str(id_)
            clear_str(password_hash)
            clear_str(contact_hash)
            print("Couldn't sign in, try again.")
        else:
            # decode succeeded, i.e. correct email and password
            clear_str(email)
            clear_str(password)
            clear_str(id_)
            clear_str(password_hash)
            print(f"Username and Password verified. Welcome, {user_info['name']}.")
            return contact_hash
