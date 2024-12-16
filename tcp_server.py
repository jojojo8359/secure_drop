from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key, ec_bytes_to_pub_key, ec_verify, \
    get_shared_key
from tcp import get_local_ip, send_checksum, recv_checksum, send_encrypted, \
    gen_shared_bundle
import socket
import ssl
import time
import os
from cryptography import x509


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
