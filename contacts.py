import os
import json
from Crypto.Cipher import AES
from hash import *

users_file: str = "users.json"
contacts_file: str = "contacts"

def encrypt_contacts_file(data, hash: str):
    cipher_aes = AES.new(bytes.fromhex(hash), AES.MODE_SIV)
    json_obj = json.dumps(data).encode("utf-8")
    ciphertext, tag = cipher_aes.encrypt_and_digest(json_obj)
    with open(contacts_file, 'wb') as f:
        f.write(tag)
        f.write(ciphertext)

def decrypt_contacts_file(hash: str):
    if not os.path.exists(contacts_file):
        print("No contacts saved")
        return
    # Open file as raw bytes
    with open(contacts_file, 'rb') as f:
        tag = f.read(16)
        ciphertext = f.read()
    # Decrypt raw bytes
    cipher_aes = AES.new(bytes.fromhex(hash), AES.MODE_SIV)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    # De-JSONify
    return json.loads(data.decode("utf-8"))

def add_contact(contact_hash: str):
    contact_name = input("Enter Full Name: ")
    contact_email = input("Enter Email Address: ")
    contacts = {}
    if os.path.exists(contacts_file):
        contacts = decrypt_contacts_file(contact_hash)
    contacts[contact_email] = contact_name
    encrypt_contacts_file(contacts, contact_hash)
    print("Contact added.")

def list_contacts(contact_hash: str):
    contacts = decrypt_contacts_file(contact_hash)
    # Go through contacts, however the internal structure is set up
    for email in contacts.keys():
        print(contacts[email] + " <" + email + ">")
