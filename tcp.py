import struct
import ssl
import socket
from typing import Union
from ecdh import ec_gen_private_key, ec_pub_key_to_bytes, ec_sign
from hash import encrypt_b, decrypt_b
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Hash import SHA3_256


def get_local_ip():
    """Helper function to get the local IP address of the current user."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def send_msg(sock: ssl.SSLSocket, msg: bytes) -> None:
    """
    Send a message over a provided SSL socket.

    Constructs a custom message type that includes the size of the data
    before the data. The maximum size of the data is 4GiB (unsigned int limit).
    """
    # Prefix each message with an 4-byte length (network byte order)
    packed_msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(packed_msg)


def recv_msg(sock: ssl.SSLSocket) -> Union[bytes, None]:
    """
    Receive a message over a provided SSL socket.

    Reads the custom message type as defined in send_msg(): size, data.

    If the data length cannot be read, returns None. Otherwise, returns the
    received data as bytes.
    """
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    return recvall(sock, msglen)


def send_checksum(sock: ssl.SSLSocket, msg: bytes) -> None:
    """
    Send a message over a provided SSL socket, using a SHA3-256 checksum.

    Prepends the data with the checksum, then uses send_msg() to send the hash
    and data.
    """
    hash = SHA3_256.new()
    hash.update(msg)
    send_msg(sock, hash.digest() + msg)


def recv_checksum(sock: ssl.SSLSocket) -> Union[bytes, None]:
    """
    Receive a message over a provided SSL socket, verifying the included
    checksum.

    If the received data does not contain a checksum or the checksum does
    not match the data, returns None. Otherwise, returns the received data
    (not including checksum) as bytes. Calls recv_msg() internally.
    """
    msg = recv_msg(sock)
    # Checksum is 32 bytes
    if not msg or len(msg) <= 32:
        return None
    checksum = msg[0:32]
    msg_body = msg[32:]
    hash = SHA3_256.new()
    hash.update(msg_body)
    if checksum == hash.digest():
        return msg_body
    print("Checksum does not match")
    return None


def send_encrypted(sock: ssl.SSLSocket, msg: bytes, shared_key: bytes) -> None:
    """
    Encrypt and send a message over a provided SSL socket (also using a
    checksum).

    Prepends the data with the encryption MAC tag, then uses send_checksum()
    to send the tag and data.
    """
    encrypted_msg, tag = encrypt_b(msg, shared_key)
    send_checksum(sock, tag + encrypted_msg)


def recv_encrypted(sock: ssl.SSLSocket, shared_key: bytes) -> Union[bytes,
                                                                    None]:
    """
    Receive and decrypt a message over a provided SSL socket, verifying the
    included checksum.

    If the received data does not include an encryption MAC tag, returns None.
    Otherwise,
    returns the received data (not including the MAC tag) as bytes. Calls
    recv_checksum() internally.
    """
    msg = recv_checksum(sock)
    # Tag is 16 bytes
    if not msg or len(msg) <= 16:
        return None
    tag = msg[0:16]
    encrypted_msg = msg[16:]
    return decrypt_b(encrypted_msg, tag, shared_key)


def recvall(sock: ssl.SSLSocket, n: int) -> Union[bytes, None]:
    """
    Helper function to receive a full message based on its length.

    If a portion of the data never arrives, returns None. Otherwise, returns
    the full chunk of data as bytes.
    """
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)


def gen_shared_bundle(signing_key: ec.EllipticCurvePrivateKey) \
        -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    """
    Generate a data key "bundle," which contains:
    - an EC private key (as an ec.EllipticCurvePrivateKey object)
    - the corresponding EC public key (as bytes, encoded in DER format)
    - the signature of the EC public key, as signed by the provided signing
    key (in bytes form)
    """
    key = ec_gen_private_key()
    key_pub = key.public_key()
    key_pub_bytes = ec_pub_key_to_bytes(key_pub)
    return (key, key_pub_bytes, ec_sign(signing_key, key_pub_bytes))
