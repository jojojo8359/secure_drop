import os
import socket
import threading

from contacts import decrypt_contacts_file
from hash import id_hash
from networking import get_udp_server_socket, receive_file
from registration import USERS_FILE, register_user, login
from shell import shell
from util import get_yes_or_no
import last_input


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
        udp_server_socket.settimeout(1)

        while last_input.last_input != 'exit':
            shell_stop_event = threading.Event()
            shell_thread = threading.Thread(target=shell, args=(contact_hash, user_id, shell_stop_event))
            shell_thread.start()

            while shell_thread.is_alive():
                try:
                    data, sender_address = udp_server_socket.recvfrom(4096)
                except socket.timeout:
                    continue
                else:
                    # received data from socket
                    data = data.decode('utf-8')
                    received_id: str = data[:-4]
                    mode: str = data[-4:]
                    contact_name: str = ''
                    contact_email: str = ''

                    contacts_list: dict[str, str] = decrypt_contacts_file(contact_hash)
                    for contact in contacts_list:
                        if received_id == id_hash(contact):
                            udp_server_socket.sendto(user_id.encode('utf-8'), sender_address)
                            contact_email = contact
                            contact_name = contacts_list[contact]
                            if mode == 'send':
                                contact_email = contact
                                contact_name = contacts_list[contact]
                            else:
                                del contacts_list, sender_address
                            del data
                            break

                    # user received a file transfer request:
                    if contact_name != '' and mode == 'send':
                        input_prompt = \
                            f"\n  Contact '{contact_name} < {contact_email} >' is sending a file. Accept (y/n)? "
                        del contact_name, contact_email
                        print(input_prompt, end='')
                        shell_stop_event.set()
                        shell_thread.join()
                        if get_yes_or_no(input_prompt, last_input.last_input):
                            # broadcast a signal saying they do accept file transfer
                            receive_file(user_id, received_id, sender_address)
                        else:
                            # broadcast a signal saying they do not accept file transfer
                            pass
                        del input_prompt

        del user_id, contact_hash


if __name__ == "__main__":
    start()
