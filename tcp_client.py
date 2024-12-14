from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key
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
                time.sleep(1)
        except ssl.SSLCertVerificationError as e:
            print("ERROR: SSL connection failed due to certificate verification: " + e.reason)
            sys.exit(1)
    finally:
        print("Client: connection closed")
        sock.close()
