import socket
import threading
import time
from tcp import server, client


SERVER_IP = "0.0.0.0"
BROADCAST_IP = "255.255.255.255"
PORT = 9999


def get_udp_server_socket() -> socket.socket:
    """
    Creates the UDP socket that runs in the background
    """
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((SERVER_IP, PORT))
    return udp_socket


def broadcast_id(id_: str, received_list: list[str], addr_list: list,
                 stop_event: threading.Event, mode: str) -> None:
    """
    Broadcasts user ID via UDP, appends any user which had the ID in their
    contacts to received_list

    mode: ping (see which contacts are online) or send (want to send file to a
    specific user)
    """

    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    broadcast_socket.sendto((id_+mode).encode('utf-8'), (BROADCAST_IP, PORT))

    broadcast_socket.settimeout(1)
    while not stop_event.is_set():
        try:
            data, address = broadcast_socket.recvfrom(4096)
            received_list.append(data.decode('utf-8'))
            if mode == 'look':
                addr_list.append(address)

        except socket.timeout:
            continue

    broadcast_socket.close()


def get_mutual_contacts_list(id_: str, received_list: list[str],
                             addr_list: list, mode: str) -> None:
    """
    Gets a list of mutual contacts between the current user and all other
    online users by utilizing the broadcast_id() method.

    id_ is the current user's id. After running, received_list will contain
    all mutual contact ids on the network. If mode is 'look', addr_list will
    contain the IP addresses of the mutual contacts in received_list.
    """
    stop_event = threading.Event()
    thread = threading.Thread(target=broadcast_id,
                              args=(id_, received_list, addr_list, stop_event,
                                    mode))
    thread.start()
    time.sleep(1)
    stop_event.set()
    thread.join()


def send_file(my_id: str, target_id: str, target_email: str, file_path: str) \
        -> None:
    """
    Send a file (at file_path) to a user with the target_id present on the
    network. target_email is used for display purposes only.
    """
    id_list = []
    addr_list = []
    get_mutual_contacts_list(my_id, id_list, addr_list, 'look')

    if target_id not in id_list:
        print(f"Contact < {target_email} > not found.")
        del id_list, addr_list
        return

    target_address = addr_list[id_list.index(target_id)]

    del id_list, addr_list

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.sendto((my_id+'send').encode('utf-8'), target_address)

    server(my_id, target_id, file_path)


def receive_file(my_id: str, target_id: str, address) -> None:
    """
    Receive a file from target_id, who should have a TCP server open at
    address.
    """
    client(my_id, target_id, address)
