import struct, ssl
from typing import Union

# TODO: embed SHA3-256 checksum at beginning of message
# this would require adding 256 bits to the beginning of the message

def send_msg(sock: ssl.SSLSocket, msg: bytes) -> None:
    # Prefix each message with an 4-byte length (network byte order)
    packed_msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(packed_msg)

def recv_msg(sock: ssl.SSLSocket) -> Union[bytearray, None]:
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def recvall(sock: ssl.SSLSocket, n: int) -> Union[bytearray, None]:
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data
