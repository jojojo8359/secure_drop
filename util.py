from getpass import getpass

def get_nonempty_input(prompt_str: str, reprompt_str: str) -> str:
    """
    Gets a non-empty string as input from the user.
    
    Uses prompt_str as the string to prompt the user for input, and reprompt_str
    as the string to re-prompt the user for input after empty input is entered.
    """
    while True:
        s: str = input(prompt_str).strip()
        if s != "":
            break
        print(reprompt_str)
    return s

def get_name() -> str:
    """Prompts the user for a full name."""
    return get_nonempty_input("Enter Full Name: ", "Please enter a name.")

def get_email() -> str:
    """Prompts the user for an email address."""
    return get_nonempty_input("Enter Email Address: ", "Please enter an email.")

def get_password_register() -> str:
    """
    Prompts the user to enter a password, with two separate inputs for
    validation, in order to register them as a user. Uses getpass to hide
    password inputs.
    """
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
    return password1

def get_password() -> str:
    """
    Prompts the user to enter a password using getpass to hide password inputs.
    """
    return getpass("Enter Password: ")
