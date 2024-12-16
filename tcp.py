import struct
import ssl
import socket
import time
import os
from typing import Union
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key, ec_pub_key_to_bytes, \
    ec_bytes_to_pub_key, ec_sign, ec_verify, get_shared_key
from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from hash import encrypt_b, decrypt_b
from Crypto.Hash import SHA3_256
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec


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


def server(my_id: str, peer_id: str, filepath: str) -> None:
    """
    Opens a TCP server to send a file securely over SSL.
    """
    if not os.path.exists(filepath):
        print("File doesn't exist, exiting...")
        return

    my_ip = get_local_ip()

    signing_key = ec_gen_private_key()
    save_private_key(signing_key, CLIENT_KEY_FILE)
    csr = build_csr(signing_key, my_id)
    cert = sign_csr(csr)
    del csr
    if cert is None:
        print("Couldn't generate a certificate for server")
        del cert
        return
    if not validate_cert(cert, my_id):
        print("Couldn't validate certificate for server")
        del cert
        return
    save_cert(cert, CLIENT_CERT_FILE)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
    context.load_verify_locations(cafile=CA_CERT_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(10.0)
        sock.bind((my_ip, 6666))
        sock.listen(2)
        with context.wrap_socket(sock, server_side=True) as ssock:
            print("Waiting for peer to accept...")
            try:
                conn, addr = ssock.accept()
            except ssl.SSLError as e:
                print("ERROR: SSL connection failed: " + e.strerror)
                return
            except socket.timeout:
                print("Peer did not connect in time.")
                return
            ssock.settimeout(None)
            try:
                try:
                    conn.do_handshake(block=True)
                except Exception:
                    print("Server: handshake: connection dropped by peer, "
                          "exiting...")
                    return

                print("Peer connected.")

                try:
                    peer_cert_der = conn.getpeercert(binary_form=True)
                except Exception:
                    print("Server: peer cert: connection dropped by peer, "
                          "exiting...")
                    return

                peer_cert = x509.load_der_x509_certificate(peer_cert_der)
                if validate_cert(peer_cert, peer_id):
                    print("Validated peer identity!")
                else:
                    print("Server: couldn't validate client certificate! "
                          "Closing connection...")
                    conn.shutdown(socket.SHUT_RDWR)
                    return

                data_key, data_key_pub, data_key_pub_sig = \
                    gen_shared_bundle(signing_key)

                # Sync - send ready
                try:
                    send_checksum(conn, 'ready'.encode())
                except Exception:
                    print("Server: s-sync: connection dropped by peer, "
                          "exiting...")
                    return

                # Sync - receive ready
                try:
                    sync_msg = recv_checksum(conn)
                except Exception:
                    print("Server: r-sync: connection dropped by peer, "
                          "exiting...")
                    return

                if sync_msg is None or sync_msg.decode() != 'ready':
                    conn.shutdown(socket.SHUT_RDWR)
                    print("Server: received sync message corrupted, "
                          "exiting...")
                    return

                try:
                    send_checksum(conn, data_key_pub_sig)
                    send_checksum(conn, data_key_pub)
                except Exception:
                    print("Server: s-key: connection dropped by peer, "
                          "exiting...")
                    return

                try:
                    peer_data_key_pub_sig = recv_checksum(conn)
                    peer_data_key_pub_bytes = recv_checksum(conn)
                except Exception:
                    print("Server: r-key: connection dropped by peer, "
                          "exiting...")
                    return

                if peer_data_key_pub_bytes is None or \
                        peer_data_key_pub_sig is None:
                    conn.shutdown(socket.SHUT_RDWR)
                    print("Server: received data corrupted, exiting...")
                    return

                peer_data_key_pub = \
                    ec_bytes_to_pub_key(peer_data_key_pub_bytes)
                if not ec_verify(peer_cert.public_key(),
                                 peer_data_key_pub_sig,
                                 peer_data_key_pub_bytes):
                    conn.shutdown(socket.SHUT_RDWR)
                    print("Server: couldn't verify signature of public key, "
                          "exiting...")
                    return

                shared_key = get_shared_key(data_key, peer_data_key_pub)

                print("Secure connection established.")

                if not os.path.exists(filepath):
                    conn.shutdown(socket.SHUT_RDWR)
                    print("File doesn't exist, exiting...")
                    return

                print("Loading file...")
                with open(filepath, 'rb') as f:
                    data = f.read()

                try:
                    send_encrypted(conn, os.path.basename(filepath).encode(),
                                   shared_key)
                    print("Sending file...")
                    send_encrypted(conn, data, shared_key)
                    print("File sent!")
                except Exception:
                    print("Server: file: connection dropped by peer, "
                          "exiting...")
                    return

                time.sleep(1)
            finally:
                print("Closed connection.")
                conn.close()
                sock.close()
                os.remove(CLIENT_CERT_FILE)
                os.remove(CLIENT_KEY_FILE)


def client(my_id: str, peer_id: str, peer_address):
    """
    Opens a TCP client to receive a file securely over SSL.
    """
    signing_key = ec_gen_private_key()
    save_private_key(signing_key, CLIENT_KEY_FILE)
    csr = build_csr(signing_key, my_id)
    cert = sign_csr(csr)
    del csr
    if cert is None:
        print("Couldn't generate a certificate for client")
        del cert
        return
    if not validate_cert(cert, my_id):
        print("Couldn't validate certificate for client")
        del cert
        return
    save_cert(cert, CLIENT_CERT_FILE)

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                         cafile=CA_CERT_FILE)
    context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)

    try:
        with socket.create_connection((peer_address, 6666)) as sock:
            try:
                try:
                    with context.wrap_socket(sock, server_side=False,
                                             server_hostname=peer_id) as ssock:
                        print("Connection upgraded to SSL.")

                        try:
                            ssock.do_handshake(block=True)
                        except Exception:
                            print("Client: handshake: connection dropped by "
                                  "peer, exiting...")
                            return

                        print("Connected to peer.")

                        try:
                            peer_cert_der = ssock.getpeercert(binary_form=True)
                        except Exception:
                            print("Client: peer cert: connection dropped by "
                                  "peer, exiting...")
                            return

                        peer_cert = \
                            x509.load_der_x509_certificate(peer_cert_der)
                        if validate_cert(peer_cert, peer_id):
                            print("Validated peer identity!")
                        else:
                            print("Client: couldn't validate server "
                                  "certificate! Closing connection...")
                            ssock.shutdown(socket.SHUT_RDWR)
                            return

                        data_key, data_key_pub, data_key_pub_sig = \
                            gen_shared_bundle(signing_key)

                        # Sync - receive ready
                        try:
                            sync_msg = recv_checksum(ssock)
                        except Exception:
                            print("Client: r-sync: connection dropped by peer,"
                                  " exiting...")
                            return

                        if sync_msg is None or sync_msg.decode() != 'ready':
                            ssock.shutdown(socket.SHUT_RDWR)
                            print("Client: received sync message corrupted, "
                                  "exiting...")
                            return

                        # Sync - send ready
                        try:
                            send_checksum(ssock, 'ready'.encode())
                        except Exception:
                            print("Client: s-sync: connection dropped by peer,"
                                  " exiting...")
                            return

                        # Receive public key signature
                        try:
                            peer_data_key_pub_sig = recv_checksum(ssock)
                            peer_data_key_pub_bytes = recv_checksum(ssock)
                        except Exception:
                            print("Client: r-key: connection dropped by peer, "
                                  "exiting...")
                            return

                        if peer_data_key_pub_bytes is None or \
                                peer_data_key_pub_sig is None:
                            ssock.shutdown(socket.SHUT_RDWR)
                            print("Client: received data corrupted, "
                                  "exiting...")
                            return

                        peer_data_key_pub = \
                            ec_bytes_to_pub_key(peer_data_key_pub_bytes)
                        if not ec_verify(peer_cert.public_key(),
                                         peer_data_key_pub_sig,
                                         peer_data_key_pub_bytes):
                            print("Client: couldn't verify signature of "
                                  "public key, exiting...")
                            ssock.shutdown(socket.SHUT_RDWR)
                            return

                        try:
                            send_checksum(ssock, data_key_pub_sig)
                            send_checksum(ssock, data_key_pub)
                        except Exception:
                            print("Client: s-key: connection dropped by peer, "
                                  "exiting...")
                            return

                        shared_key = get_shared_key(data_key,
                                                    peer_data_key_pub)

                        print("Secure connection established.")

                        try:
                            filename = recv_encrypted(ssock,
                                                      shared_key).decode()
                            print("Receiving file...")
                            data = recv_encrypted(ssock, shared_key)
                        except Exception:
                            print("Client: data: connection dropped by peer, "
                                  "exiting...")
                            return

                        if not os.path.isdir("files"):
                            os.mkdir("files")
                        print("Saving file...")
                        with open(os.path.join("files", filename), 'wb') as f:
                            f.write(data)
                        print("File successfully transfered!")

                        time.sleep(1)
                except ssl.SSLCertVerificationError as e:
                    print("ERROR: SSL connection failed due to certificate "
                          "verification: " + e.strerror)
                    return
            finally:
                print("Connection closed.")
                sock.close()
                os.remove(CLIENT_CERT_FILE)
                os.remove(CLIENT_KEY_FILE)
    except ConnectionRefusedError:
        print("Couldn't connect to peer.")
        return
