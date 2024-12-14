from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key, ec_pub_key_to_bytes, ec_bytes_to_pub_key, ec_sign, ec_verify, get_shared_key
from tcp import send_msg, recv_msg
import socket, ssl, argparse, sys, time
from cryptography import x509

# RECEIVER
parser = argparse.ArgumentParser(prog="tcp_client", description="Receive files with encryption and authentication")
parser.add_argument('host_address', type=str, help='IP Address of the server to connect to')
parser.add_argument('host_port', type=int, help='Port number of the server to connect to')
parser.add_argument('email', type=str, help='The user\'s email')
parser.add_argument('peer_email', type=str, help='The email of the user to connect to')
args = parser.parse_args()


signing_key = ec_gen_private_key()
save_private_key(CLIENT_KEY_FILE, signing_key)
csr = build_csr(signing_key, args.email)
cert = sign_csr(csr)
if cert == None:
    print("Couldn't generate a certificate for server")
    sys.exit(1)
if not validate_cert(cert, args.email):
    print("Coudln't validate certificate for server")
    sys.exit(1)

save_cert(CLIENT_CERT_FILE, cert)


context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT_FILE)
context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)

with socket.create_connection((args.host_address, args.host_port)) as sock:
    try:
        print("Client: connection established to " + args.host_address + ":" + str(args.host_port))
        try:
            with context.wrap_socket(sock, server_side=False, server_hostname=args.peer_email) as ssock:
                print("Client: connection upgraded to SSL")
                print(ssock.version())
                ssock.do_handshake(block=True)
                print("Client: handshake done")
                peer_cert = x509.load_der_x509_certificate(ssock.getpeercert(binary_form=True))
                if validate_cert(peer_cert, args.peer_email):
                    print("Client: successfully validated server certificate!")
                else:
                    print("Client: couldn't validate server certificate! Closing connection...")
                    ssock.shutdown(socket.SHUT_RDWR)
                
                # Sync - receive ready
                # TODO: connection drop handling
                print("Waiting to receive sync message...")
                sync_msg = recv_msg(ssock)
                if sync_msg.decode() == 'ready':
                    print("Received sync message")
                    # Sync - send ready
                    send_msg(ssock, 'ready'.encode())
                    print("Sent sync message")
                else:
                    print("Sync message corrupted, exiting...")
                    ssock.shutdown(socket.SHUT_RDWR)
                
                # Receive public key signature
                peer_data_key_pub_sig = recv_msg(ssock)
                print("Peer pub key signature received")
                print("Peer pub key signature: " + peer_data_key_pub_sig.hex())
                
                peer_data_key_pub_bytes = recv_msg(ssock)
                print("Peer pub key received")
                print("Peer pub key: " + peer_data_key_pub_bytes.hex())
                peer_data_key_pub = ec_bytes_to_pub_key(bytes(peer_data_key_pub_bytes))
                if not ec_verify(peer_cert.public_key(), bytes(peer_data_key_pub_sig), peer_data_key_pub):
                    print("Client: couldn't verify signature of public key, exiting...")
                    ssock.shutdown(socket.SHUT_RDWR)
                
                data_key = ec_gen_private_key()
                data_key_pub: bytes = ec_pub_key_to_bytes(data_key.public_key())
                data_key_pub_sig: bytes = ec_sign(signing_key, data_key_pub)
                
                print("My pub key signature: " + data_key_pub_sig.hex())
                send_msg(ssock, data_key_pub_sig)
                print("My pub key signature sent")
                
                print("My pub key: " + data_key_pub.hex())
                send_msg(ssock, data_key_pub)
                print("My pub key sent")
                
                shared_key = get_shared_key(data_key, peer_data_key_pub)
                print("Shared key: " + shared_key.hex())
                
                time.sleep(1)
        except ssl.SSLCertVerificationError as e:
            print("ERROR: SSL connection failed due to certificate verification: " + e.strerror)
            sys.exit(1)
    finally:
        print("Client: connection closed")
        sock.close()
