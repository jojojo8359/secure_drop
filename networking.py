import socket
import threading

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


def broadcast_id(id_: str, received_list: list[str], stop_event: threading.Event) -> None:
    """
    Broadcasts user ID via UDP, appends any user which had the ID in their contacts to received_list
    """

    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    broadcast_socket.sendto(id_.encode('utf-8'), (BROADCAST_IP, PORT))

    broadcast_socket.settimeout(1)
    while not stop_event.is_set():
        try:
            data, _ = broadcast_socket.recvfrom(4096)
            received_list.append(data.decode('utf-8'))
        except socket.timeout:
            continue

    broadcast_socket.close()
