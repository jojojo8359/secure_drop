import threading

from contacts import add_contact, list_contacts


global last_input
last_input: str


def shell(contact_hash: str, user_id: str, stop_event: threading.Event) -> None:
    global last_input
    while not stop_event.is_set():
        last_input = comm = input("secure_drop> ").lower().strip()
        if comm == "add":
            add_contact(contact_hash)
        elif comm == "list":
            list_contacts(contact_hash, user_id)
        elif comm == "help":
            print("  \"add\"  -> Add a new contact")
            print("  \"list\" -> List all online contacts")
            print("  \"send\" -> Transfer file to contact")
            print("  \"exit\" -> Exit SecureDrop")
        elif comm == "exit":
            break
        elif comm == "send":
            print("File transfer not yet implemented.")
        elif comm == "":
            continue
        else:
            print("Command not recognized.")
