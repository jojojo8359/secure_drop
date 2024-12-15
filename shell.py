import threading

from contacts import add_contact, list_contacts, get_contact_id
import last_input
from networking import send_file
import os


def shell(contact_hash: str, user_id: str, stop_event: threading.Event) -> None:
    # TODO: Add documentation
    comm: list[str] = ['']
    while not stop_event.is_set():
        if comm[0] == "add":
            add_contact(contact_hash, user_id)
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
            if len(comm) != 3:
                print("send command should be used as follows: \"send <email> <filepath>\"")
            else:
                receiver_id: str = get_contact_id(comm[1], contact_hash)
                if receiver_id == '':
                    print(f"Contact < {comm[1]} > not found.")
                else:
                    file_path = comm[2]
                    if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                        print("File " + file_path + " doesn't exist!")
                    elif os.path.isdir(file_path):
                        print(file_path + " is a directory, not a file!")
                    else:
                        if os.stat(file_path).st_size >= 4294967290:
                            print("File " + file_path + " is too large! (Max = 4GiB)")
                        else:
                            send_file(user_id, receiver_id, comm[1], file_path)
        elif comm[0] == "":
            pass
        else:
            print("Command not recognized.")

        comm = input("secure_drop> ").lower().strip().split(' ')
        last_input.last_input = comm[0]
