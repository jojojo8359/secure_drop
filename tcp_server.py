from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key, ec_bytes_to_pub_key, ec_verify, get_shared_key
from tcp import get_local_ip, send_checksum, recv_checksum, send_encrypted, recv_encrypted, gen_shared_bundle
import socket, ssl, argparse, sys, time, os
from cryptography import x509

# SENDER
# parser = argparse.ArgumentParser(prog="tcp_server", description="Receive files with encryption and authentication")
# parser.add_argument('host_address', type=str, help='IP Address of the server to host')
# parser.add_argument('host_port', type=int, help='Port number of the server to host')
# parser.add_argument('email', type=str, help='The user\'s email')
# parser.add_argument('peer_email', type=str, help='The email of the user to connect to')
# args = parser.parse_args()

def server(my_id: str, peer_id: str, filepath: str) -> None:
    my_ip = get_local_ip()
    
    signing_key = ec_gen_private_key()
    save_private_key(CLIENT_KEY_FILE, signing_key)
    csr = build_csr(signing_key, my_id)
    cert = sign_csr(csr)
    del csr
    if cert == None:
        print("Couldn't generate a certificate for server")
        del cert
        return
    if not validate_cert(cert, my_id):
        print("Couldn't validate certificate for server")
        del cert
        return
    save_cert(CLIENT_CERT_FILE, cert)
    
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
    context.load_verify_locations(cafile=CA_CERT_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((my_ip, 6666))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            print("Server: waiting for connection")
            try:
                conn, addr = ssock.accept()
            except ssl.SSLError as e:
                print("ERROR: SSL connection failed: " + e.strerror)
                return
            try:
                print(str(addr) + " connected")
                
                try:
                    conn.do_handshake(block=True)
                except:
                    # conn.shutdown(socket.SHUT_RDWR)
                    print("Server: handshake: connection dropped by peer, exiting...")
                    return
                
                print("Server: handshake done")
                
                try:
                    peer_cert_der = conn.getpeercert(binary_form=True)
                except:
                    # conn.shutdown(socket.SHUT_RDWR)
                    print("Server: peer cert: connection dropped by peer, exiting...")
                    return
                
                
                peer_cert = x509.load_der_x509_certificate(peer_cert_der)
                if validate_cert(peer_cert, peer_id):
                    print("Server: successfully validated client certificate!")
                else:
                    print("Server: couldn't validate client certificate! Closing connection...")
                    conn.shutdown(socket.SHUT_RDWR)
                    return
                
                data_key, data_key_pub, data_key_pub_sig = gen_shared_bundle(signing_key)

                # Sync - send ready
                try:
                    send_checksum(conn, 'ready'.encode())
                except:
                    # conn.shutdown(socket.SHUT_RDWR)
                    print("Server: s-sync: connection dropped by peer, exiting...")
                    return
                
                # Sync - receive ready
                try:
                    sync_msg = recv_checksum(conn)
                except:
                    # conn.shutdown(socket.SHUT_RDWR)
                    print("Server: r-sync: connection dropped by peer, exiting...")
                    return

                if sync_msg == None or sync_msg.decode() != 'ready':
                    conn.shutdown(socket.SHUT_RDWR)
                    print("Server: received sync message corrupted, exiting...")
                    return
                
                try:
                    send_checksum(conn, data_key_pub_sig)
                    send_checksum(conn, data_key_pub)
                except:
                    # conn.shutdown(socket.SHUT_RDWR)
                    print("Server: s-key: connection dropped by peer, exiting...")
                    return
                
                try:
                    peer_data_key_pub_sig = recv_checksum(conn)
                    peer_data_key_pub_bytes = recv_checksum(conn)
                except:
                    # conn.shutdown(socket.SHUT_RDWR)
                    print("Server: r-key: connection dropped by peer, exiting...")
                    return
                
                if peer_data_key_pub_bytes == None or peer_data_key_pub_sig == None:
                    conn.shutdown(socket.SHUT_RDWR)
                    print("Server: received data corrupted, exiting...")
                    return
                
                peer_data_key_pub = ec_bytes_to_pub_key(peer_data_key_pub_bytes)
                if not ec_verify(peer_cert.public_key(), peer_data_key_pub_sig, peer_data_key_pub_bytes):
                    conn.shutdown(socket.SHUT_RDWR)
                    print("Server: couldn't verify signature of public key, exiting...")
                    return
                
                shared_key = get_shared_key(data_key, peer_data_key_pub)
                print("Shared key: " + shared_key.hex())
                
                # filename = input("Choose a file to transfer: ").strip()
                if not os.path.exists(filepath):
                    conn.shutdown(socket.SHUT_RDWR)
                    print("File doesn't exist, exiting...")
                    return
                
                print("Loading file...")
                with open(filepath, 'rb') as f:
                    data = f.read()
                
                try:
                    send_encrypted(conn, os.path.basename(filepath).encode(), shared_key)
                    print("Sending file...")
                    send_encrypted(conn, data, shared_key)
                    print("File sent!")
                except:
                    conn.shutdown(socket.SHUT_RDWR)
                    print("Server: file: connection dropped by peer, exiting...")
                    sys.exit(1)
                
                time.sleep(1)
            finally:
                print("Server: connection closed")
                conn.close()
                os.remove(CLIENT_CERT_FILE)
                os.remove(CLIENT_KEY_FILE)
