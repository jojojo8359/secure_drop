import os
import sys
from registration import USERS_FILE, register_user, login
from contacts import add_contact, list_contacts
from util import input_yes_or_no


if __name__ == "__main__":
    # if the users file doesn't exist, ask if we want to register a new user to
    # create the file
    if not os.path.exists(USERS_FILE):
        # ask if the user wants to register a new user
        print("No users are registered with this client.")
        if input_yes_or_no("Do you want to register a new user (y/n)? "):
            register_user()
        else:
            # quit program
            print("Goodbye!")
            sys.exit(0)
    # if the users file does exist, have the user log in and enter the shell
    else:
        contact_hash = login()
        # Shell goes here
        comm: str = ""
        while True:
            comm = input("secure_drop> ").lower().strip()
            if comm == "add":
                add_contact(contact_hash)
            elif comm == "list":
                list_contacts(contact_hash)
            elif comm == "help":
                print("  \"add\"  -> Add a new contact")
                # TODO: Change to "online contacts" for final milestones
                print("  \"list\" -> List all contacts")
                print("  \"send\" -> Transfer file to contact")
                print("  \"exit\" -> Exit SecureDrop")
            elif comm == "exit":
                break
            elif comm == "send":
                print("File transfer not yet implemented")
            else:
                print("Command not recognized")
