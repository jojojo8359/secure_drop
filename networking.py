import socket
import threading
import time


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


def broadcast_id(id_: str, received_list: list[str], addr_list: list, stop_event: threading.Event, mode: str) -> None:
    """
    Broadcasts user ID via UDP, appends any user which had the ID in their contacts to received_list

    mode: ping (see which contacts are online) or send (want to send file to a specific user)
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


def get_mutual_contacts_list(id_: str, received_list: list[str], addr_list: list, mode: str) -> None:
    stop_event = threading.Event()
    thread = threading.Thread(target=broadcast_id, args=(id_, received_list, addr_list, stop_event, mode))
    thread.start()
    time.sleep(1)
    stop_event.set()
    thread.join()


def send_file(my_id: str, target_id: str, target_email: str, file_path: str) -> None:
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

    # here we do the sender code
    
    print("I am opening a TCP server now")



def receive_file(address) -> None:
    # here we do the receiver code
    print("I am opening a TCP client now")
