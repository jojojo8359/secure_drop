from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key, ec_pub_key_to_bytes, ec_bytes_to_pub_key, ec_sign, ec_verify, get_shared_key
from tcp import send_msg, recv_msg, gen_shared_bundle
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
                
                try:
                    ssock.do_handshake(block=True)
                except:
                    ssock.shutdown(socket.SHUT_RDWR)
                    print("Client: connection dropped by peer, exiting...")
                    sys.exit(1)
                
                print("Client: handshake done")
                
                try:
                    peer_cert_der = ssock.getpeercert(binary_form=True)
                except:
                    ssock.shutdown(socket.SHUT_RDWR)
                    print("Client: connection dropped by peer, exiting...")
                    sys.exit(1)
                
                peer_cert = x509.load_der_x509_certificate(peer_cert_der)
                if validate_cert(peer_cert, args.peer_email):
                    print("Client: successfully validated server certificate!")
                else:
                    print("Client: couldn't validate server certificate! Closing connection...")
                    ssock.shutdown(socket.SHUT_RDWR)
                    sys.exit(1)
                
                data_key, data_key_pub, data_key_pub_sig = gen_shared_bundle(signing_key)
                
                # Sync - receive ready
                try:
                    sync_msg = recv_msg(ssock)
                except:
                    ssock.shutdown(socket.SHUT_RDWR)
                    print("Client: connection dropped by peer, exiting...")
                    sys.exit(1)
                
                if sync_msg == None or sync_msg.decode() != 'ready':
                    ssock.shutdown(socket.SHUT_RDWR)
                    print("Client: received sync message corrupted, exiting...")
                    sys.exit(1)
                
                # Sync - send ready
                try:
                    send_msg(ssock, 'ready'.encode())
                except:
                    ssock.shutdown(socket.SHUT_RDWR)
                    print("Client: connection dropped by peer, exiting...")
                    sys.exit(1)
                
                # Receive public key signature
                try:
                    peer_data_key_pub_sig = recv_msg(ssock)
                    peer_data_key_pub_bytes = recv_msg(ssock)
                except:
                    ssock.shutdown(socket.SHUT_RDWR)
                    print("Client: connection dropped by peer, exiting...")
                    sys.exit(1)
                
                if peer_data_key_pub_bytes == None:
                    ssock.shutdown(socket.SHUT_RDWR)
                    print("Client: received data public key corrupted, exiting...")
                    sys.exit(1)
                
                peer_data_key_pub = ec_bytes_to_pub_key(peer_data_key_pub_bytes)
                if not ec_verify(peer_cert.public_key(), peer_data_key_pub_sig, peer_data_key_pub_bytes):
                    print("Client: couldn't verify signature of public key, exiting...")
                    ssock.shutdown(socket.SHUT_RDWR)
                    sys.exit(1)
                
                try:
                    send_msg(ssock, data_key_pub_sig)
                    send_msg(ssock, data_key_pub)
                except:
                    ssock.shutdown(socket.SHUT_RDWR)
                    print("Client: connection dropped by peer, exiting...")
                    sys.exit(1)
                
                shared_key = get_shared_key(data_key, peer_data_key_pub)
                print("Shared key: " + shared_key.hex())
                
                time.sleep(1)
        except ssl.SSLCertVerificationError as e:
            print("ERROR: SSL connection failed due to certificate verification: " + e.strerror)
            sys.exit(1)
    finally:
        print("Client: connection closed")
        sock.close()
