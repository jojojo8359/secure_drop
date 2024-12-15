import json
import os

from filenames import CONTACTS_FILE
from hash import encrypt, decrypt, id_hash
from networking import get_mutual_contacts_list
from util import get_name, get_email


def encrypt_contacts_file(data, key: str):
    """
    Encrypts the provided data with the provided hash, and writes it to the
    contacts file.
    
    The data provided should be a dictionary or list, since it will be dumped
    by the json library to encode and encrypt.
    """
    ciphertext, tag = encrypt(json.dumps(data), key)
    with open(CONTACTS_FILE, 'wb') as f:
        f.write(tag)
        f.write(ciphertext)


def decrypt_contacts_file(key: str) -> dict[str, str]:
    """
    Decrypts the contacts file with the provided hash, and returns a Python
    dictionary with the decrypted data.
    
    If the file does not exist, an empty dictionary object will be returned.
    """
    if not os.path.exists(CONTACTS_FILE):
        return {}

    with open(CONTACTS_FILE, 'rb') as f:
        tag = f.read(16)
        ciphertext = f.read()
    return json.loads(decrypt(ciphertext, tag, key))


def add_contact(contact_hash: str) -> None:
    """
    Adds a contact to the list of contacts.
    
    The contact hash is needed to encrypt and decrypt contact data with the
    current user's (now encrypted) credentials.
    """
    contacts: dict = decrypt_contacts_file(contact_hash) if os.path.exists(CONTACTS_FILE) else {}
    contacts[get_email()] = get_name()
    encrypt_contacts_file(contacts, contact_hash)
    print("Contact added.")


def list_contacts(contact_hash: str, user_id: str) -> None:
    """
    Lists the online contacts stored in the contacts file.
    
    The contact hash is needed to decrypt contact data with the current user's
    (now encrypted) credentials.
    """
    contacts: dict[str, str] = decrypt_contacts_file(contact_hash)
    if len(contacts) < 1:
        print("  No contacts saved.")
    else:
        received_list: list[str] = []  # will have a list of hashed emails

        # run thread for 1 second to see online contacts
        get_mutual_contacts_list(user_id, received_list, [], 'ping')

        # get responses from everyone, I will get their ID back if I am in their contact
        # Go through my contacts, match IDs I get back against theirs, list them if matches

        output: str = ""
        for email, name in contacts.items():
            if id_hash(email) in received_list:
                output += f"  * {name} < {email} >\n"
        if output == "":
            print("  No contacts are online.")
        else:
            print("  The following contacts are online:\n" + output)
        del output

    del contacts


def get_contact_id(contact_email: str, contact_hash: str) -> str:
    contact_info = decrypt_contacts_file(contact_hash)
    ret_val: str = id_hash(contact_email) if contact_email in contact_info else ''
    del contact_info
    return ret_val
