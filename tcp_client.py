from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key, ec_bytes_to_pub_key, ec_verify, get_shared_key
from tcp import send_checksum, recv_checksum, send_encrypted, recv_encrypted, gen_shared_bundle
import socket, ssl, argparse, sys, time, os
from cryptography import x509

# RECEIVER
# parser = argparse.ArgumentParser(prog="tcp_client", description="Receive files with encryption and authentication")
# parser.add_argument('host_address', type=str, help='IP Address of the server to connect to')
# parser.add_argument('host_port', type=int, help='Port number of the server to connect to')
# parser.add_argument('email', type=str, help='The user\'s email')
# parser.add_argument('peer_email', type=str, help='The email of the user to connect to')
# args = parser.parse_args()


def client(my_id: str, peer_id: str, peer_address):
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
        print("Coudln't validate certificate for server")
        del cert
        return
    save_cert(CLIENT_CERT_FILE, cert)

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT_FILE)
    context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)

    with socket.create_connection((peer_address, 6666)) as sock:
        try:
            print("Client: connection established to " + peer_address + ":" + "6666")
            try:
                with context.wrap_socket(sock, server_side=False, server_hostname=peer_id) as ssock:
                    print("Client: connection upgraded to SSL")
                    print(ssock.version())
                    
                    try:
                        ssock.do_handshake(block=True)
                    except:
                        # ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: handshake: connection dropped by peer, exiting...")
                        return
                    
                    print("Client: handshake done")
                    
                    try:
                        peer_cert_der = ssock.getpeercert(binary_form=True)
                    except:
                        # ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: peer cert: connection dropped by peer, exiting...")
                        return
                    
                    peer_cert = x509.load_der_x509_certificate(peer_cert_der)
                    if validate_cert(peer_cert, peer_id):
                        print("Client: successfully validated server certificate!")
                    else:
                        print("Client: couldn't validate server certificate! Closing connection...")
                        ssock.shutdown(socket.SHUT_RDWR)
                        return
                    
                    data_key, data_key_pub, data_key_pub_sig = gen_shared_bundle(signing_key)
                    
                    # Sync - receive ready
                    try:
                        sync_msg = recv_checksum(ssock)
                    except:
                        # ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: r-sync: connection dropped by peer, exiting...")
                        return
                    
                    if sync_msg == None or sync_msg.decode() != 'ready':
                        ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: received sync message corrupted, exiting...")
                        return
                    
                    # Sync - send ready
                    try:
                        send_checksum(ssock, 'ready'.encode())
                    except:
                        # ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: s-sync: connection dropped by peer, exiting...")
                        return
                    
                    # Receive public key signature
                    try:
                        peer_data_key_pub_sig = recv_checksum(ssock)
                        peer_data_key_pub_bytes = recv_checksum(ssock)
                    except:
                        # ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: r-key: connection dropped by peer, exiting...")
                        return
                    
                    if peer_data_key_pub_bytes == None or peer_data_key_pub_sig == None:
                        ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: received data corrupted, exiting...")
                        return
                    
                    peer_data_key_pub = ec_bytes_to_pub_key(peer_data_key_pub_bytes)
                    if not ec_verify(peer_cert.public_key(), peer_data_key_pub_sig, peer_data_key_pub_bytes):
                        print("Client: couldn't verify signature of public key, exiting...")
                        ssock.shutdown(socket.SHUT_RDWR)
                        return
                    
                    try:
                        send_checksum(ssock, data_key_pub_sig)
                        send_checksum(ssock, data_key_pub)
                    except:
                        # ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: s-key: connection dropped by peer, exiting...")
                        return
                    
                    shared_key = get_shared_key(data_key, peer_data_key_pub)
                    print("Shared key: " + shared_key.hex())
                    
                    try:
                        filename = recv_encrypted(ssock, shared_key).decode()
                        print("Receiving file...")
                        data = recv_encrypted(ssock, shared_key)
                    except:
                        # ssock.shutdown(socket.SHUT_RDWR)
                        print("Client: data: connection dropped by peer, exiting...")
                        return
                    
                    if not os.path.isdir("files"):
                        os.mkdir("files")
                    print("Saving file...")
                    with open(os.path.join("files", filename), 'wb') as f:
                        f.write(data)
                    print("File successfully transfered!")
                    
                    time.sleep(1)
            except ssl.SSLCertVerificationError as e:
                print("ERROR: SSL connection failed due to certificate verification: " + e.strerror)
                return
        finally:
            print("Client: connection closed")
            sock.close()
            os.remove(CLIENT_CERT_FILE)
            os.remove(CLIENT_KEY_FILE)
