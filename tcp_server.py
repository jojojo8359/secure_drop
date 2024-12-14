from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key, ec_pub_key_to_bytes, ec_bytes_to_pub_key, ec_sign, ec_verify, get_shared_key
from tcp import send_msg, recv_msg
import socket, ssl, argparse, sys, time
from cryptography import x509

# SENDER
parser = argparse.ArgumentParser(prog="tcp_server", description="Receive files with encryption and authentication")
parser.add_argument('host_address', type=str, help='IP Address of the server to host')
parser.add_argument('host_port', type=int, help='Port number of the server to host')
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


context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
context.load_verify_locations(cafile=CA_CERT_FILE)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((args.host_address, args.host_port))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        print("Server: waiting for connection")
        try:
            conn, addr = ssock.accept()
        except ssl.SSLError as e:
            print("ERROR: SSL connection failed: " + e.strerror)
            sys.exit(1)
        try:
            print(str(addr) + " connected")
            conn.do_handshake(block=True)
            print("Server: handshake done")
            peer_cert = x509.load_der_x509_certificate(conn.getpeercert(binary_form=True))
            if validate_cert(peer_cert, args.peer_email):
                print("Server: successfully validated client certificate!")
            else:
                print("Server: couldn't validate client certificate! Closing connection...")
                conn.shutdown(socket.SHUT_RDWR)
            data_key = ec_gen_private_key()
            data_key_pub: bytes = ec_pub_key_to_bytes(data_key.public_key())
            data_key_pub_sig: bytes = ec_sign(signing_key, data_key_pub)
            
            # Sync - send ready
            send_msg(conn, 'ready'.encode())
            print("Sent sync message")
            
            # Sync - receive ready
            print("Waiting to receive sync message...")
            sync_msg = recv_msg(conn)
            if sync_msg.decode() == 'ready':
                print("Received sync message")
            else:
                print("Sync message corrupted, exiting...")
                conn.shutdown(socket.SHUT_RDWR)
            
            print("My pub key signature: " + data_key_pub_sig.hex())
            send_msg(conn, data_key_pub_sig)
            print("My pub key signature sent")
            
            print("My pub key: " + data_key_pub.hex())
            send_msg(conn, data_key_pub)
            print("My pub key sent")
            
            peer_data_key_pub_sig = recv_msg(conn)
            print("Peer pub key signature received")
            print("Peer pub key signature: " + peer_data_key_pub_sig.hex())
            
            peer_data_key_pub_bytes = recv_msg(conn)
            print("Peer pub key received")
            print("Peer pub key: " + peer_data_key_pub_bytes.hex())
            peer_data_key_pub = ec_bytes_to_pub_key(bytes(peer_data_key_pub_bytes))
            if not ec_verify(peer_cert.public_key(), bytes(peer_data_key_pub_sig), peer_data_key_pub):
                print("Server: couldn't verify signature of public key, exiting...")
                conn.shutdown(socket.SHUT_RDWR)
            
            shared_key = get_shared_key(data_key, peer_data_key_pub)
            print("Shared key: " + shared_key.hex())
            
            time.sleep(1)
        finally:
            conn.close()
            print("Server: connection closed")
