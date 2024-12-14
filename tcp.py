import struct, ssl
from typing import Union
from ecdh import ec_gen_private_key, ec_pub_key_to_bytes, ec_sign
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Hash import SHA3_256

# TODO: embed SHA3-256 checksum at beginning of message
# this would require adding 256 bits to the beginning of the message

def send_msg(sock: ssl.SSLSocket, msg: bytes) -> None:
    # Prefix each message with an 4-byte length (network byte order)
    packed_msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(packed_msg)

def recv_msg(sock: ssl.SSLSocket) -> Union[bytes, None]:
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)

def send_checksum(sock: ssl.SSLSocket, msg: bytes) -> None:
    hash = SHA3_256.new()
    hash.update(msg)
    send_msg(sock, hash.digest() + msg)

def recv_checksum(sock: ssl.SSLSocket) -> Union[bytes, None]:
    msg = recv_msg(sock)
    if not msg or len(msg) <= 32:
        return None
    checksum = msg[0:32]
    msg_body = msg[32:]
    hash = SHA3_256.new()
    hash.update(msg_body)
    if checksum == hash.digest():
        print("Checksum matches")
        return msg_body
    print("Checksum does not match")
    return None

def recvall(sock: ssl.SSLSocket, n: int) -> Union[bytes, None]:
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def gen_shared_bundle(signing_key: ec.EllipticCurvePrivateKey) -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    key = ec_gen_private_key()
    key_pub = key.public_key()
    key_pub_bytes = ec_pub_key_to_bytes(key_pub)
    return (key, key_pub_bytes, ec_sign(signing_key, key_pub_bytes))
