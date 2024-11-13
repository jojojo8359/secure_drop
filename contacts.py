import os
import json
from Crypto.Cipher import AES
from hash import *
from util import get_name, get_email

contacts_file: str = "contacts"

def encrypt_contacts_file(data, hash: str):
    """
    Encrypts the provided data with the provided hash, and writes it to the
    contacts file.
    
    The data provided should be a dictionary or list, since it will be dumped
    by the json library to encode and encrypt.
    """
    cipher_aes = AES.new(bytes.fromhex(hash), AES.MODE_SIV)
    json_obj = json.dumps(data).encode("utf-8")
    ciphertext, tag = cipher_aes.encrypt_and_digest(json_obj)
    with open(contacts_file, 'wb') as f:
        f.write(tag)
        f.write(ciphertext)

def decrypt_contacts_file(hash: str):
    """
    Decrypts the contacts file with the provided hash, and returns a Python
    dictionary with the decrypted data.
    
    If the file does not exist, an empty dictionary object will be returned.
    """
    if not os.path.exists(contacts_file):
        print("No contacts saved")
        return {}
    # Open file as raw bytes
    with open(contacts_file, 'rb') as f:
        tag = f.read(16)
        ciphertext = f.read()
    # Decrypt raw bytes
    cipher_aes = AES.new(bytes.fromhex(hash), AES.MODE_SIV)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    # De-JSONify
    return json.loads(data.decode("utf-8"))

def add_contact(contact_hash: str) -> None:
    """
    Adds a contact to the list of contacts.
    
    The contact hash is needed to encrypt and decrypt contact data with the
    current user's (now encrypted) credentials.
    """
    contact_name = get_name()
    contact_email = get_email()
    contacts = {}
    if os.path.exists(contacts_file):
        contacts = decrypt_contacts_file(contact_hash)
    contacts[contact_email] = contact_name
    encrypt_contacts_file(contacts, contact_hash)
    print("Contact added.")

def list_contacts(contact_hash: str) -> None:
    """
    Lists the current contacts stored in the contacts file.
    
    The contact hash is needed to decrypt contact data with the current user's
    (now encrypted) credentials.
    """
    contacts = decrypt_contacts_file(contact_hash)
    # Go through contacts - key = email, value = name
    for email in contacts.keys():
        print(contacts[email] + " <" + email + ">")
