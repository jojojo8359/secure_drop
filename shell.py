import threading

from contacts import add_contact, list_contacts, get_contact_id
import last_input
from networking import send_file


def shell(contact_hash: str, user_id: str, stop_event: threading.Event) -> None:
    comm: list[str] = ['']
    while not stop_event.is_set():
        if comm[0] == "add":
            add_contact(contact_hash)
        elif comm[0] == "list":
            list_contacts(contact_hash, user_id)
        elif comm[0] == "help":
            print("  \"add\"  -> Add a new contact")
            print("  \"list\" -> List all online contacts")
            print("  \"send\" -> Transfer file to contact")
            print("  \"exit\" -> Exit SecureDrop")
        elif comm[0] == "exit":
            break
        elif comm[0] == "send":
            receiver_id: str = get_contact_id(comm[1], contact_hash)
            if receiver_id == '':
                print(f"Contact < {comm[1]} > not found.")
            else:
                send_file(user_id, receiver_id, comm[1], comm[2])
        elif comm[0] == "":
            pass
        else:
            print("Command not recognized.")

        comm = input("secure_drop> ").lower().strip().split(' ')
        last_input.last_input = comm[0]
