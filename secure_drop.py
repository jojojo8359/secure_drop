import os
import sys
from registration import register_user, login
from contacts import users_file

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
