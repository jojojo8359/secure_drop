import socket
import ssl
import argparse
from filenames import CA_CERT_FILE, CLIENT_CERT_FILE, CLIENT_KEY_FILE
from ca import save_cert, save_private_key, build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key
import sys
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend

# SENDER
parser = argparse.ArgumentParser(prog="tcp_server", description="Receive files with encryption and authentication")
parser.add_argument('host_address', type=str, help='IP Address of the server to host')
parser.add_argument('host_port', type=int, help='Port number of the server to host')
parser.add_argument('email', type=str, help='The user\'s email')
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


# context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile='ca.cert.pem')
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile=CLIENT_CERT_FILE, keyfile=CLIENT_KEY_FILE)
context.load_verify_locations(cafile=CA_CERT_FILE)

# with open(args.certificate, 'rb') as f:
#     cert = x509.load_pem_x509_certificate(f.read(), default_backend())
# print(cert.subject.rdns[0])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((args.host_address, args.host_port))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        print(str(addr) + " connected")
        # pubkey = conn.recv(2048).decode()
        conn.do_handshake()
        print(conn.getpeername())
        # print(pubkey)
