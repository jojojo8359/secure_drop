import os
import sys
from registration import register_user, login
from contacts import users_file, add_contact, list_contacts

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
                print("  \"list\" -> List all contacts")  # TODO: Change to online contacts
                print("  \"send\" -> Transfer file to contact")
                print("  \"exit\" -> Exit SecureDrop")
            elif comm == "exit":
                break
            else:
                print("Command not recognized")
