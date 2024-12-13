import os
import threading

from contacts import decrypt_contacts_file
from hash import id_hash
from networking import get_udp_server_socket
from registration import USERS_FILE, register_user, login
from shell import shell
from util import get_yes_or_no


def start() -> None:
    # if the users file doesn't exist, ask if we want to register a new user to
    # create the file
    if not os.path.exists(USERS_FILE):
        # ask if the user wants to register a new user
        print("No users are registered with this client.")
        if get_yes_or_no("Do you want to register a new user (y/n)? "):
            register_user()
        else:
            # quit program
            print("Goodbye!")
    # if the users file does exist, have the user log in and enter the shell
    else:
        user_id, contact_hash = login()

        udp_server_socket = get_udp_server_socket()

        while True:
            shell_stop_event = threading.Event()
            shell_thread = threading.Thread(target=shell, args=(user_id, contact_hash, shell_stop_event))
            shell_thread.start()

            while True:
                data, sender_address = udp_server_socket.recvfrom(4096)
                data = data.decode('utf-8')

                contacts_list: dict[str, str] = decrypt_contacts_file(contact_hash)
                for contact in contacts_list:
                    if data == id_hash(contact):
                        udp_server_socket.sendto(user_id.encode('utf-8'), sender_address)
                        break
                del contacts_list

                import sys
                sys.exit(69)

        del login_info


if __name__ == "__main__":
    start()
