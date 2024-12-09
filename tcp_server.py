import socket
import ssl
import argparse
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend

# SENDER
parser = argparse.ArgumentParser(prog="tcp_server", description="Receive files with encryption and authentication")
parser.add_argument('host_address', type=str, help='IP Address of the server to host')
parser.add_argument('host_port', type=int, help='Port number of the server to host')
parser.add_argument('key', type=str, help='File with client\'s private key')
parser.add_argument('certificate', type=str, help='File with client\'s certificate')
parser.add_argument('email', type=str, help='The user\'s email')
args = parser.parse_args()

# context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile='ca.cert.pem')
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.verify_mode = ssl.CERT_REQUIRED
context.load_cert_chain(certfile=args.certificate, keyfile=args.key)
context.load_verify_locations(cafile='ca.cert.pem')

# with open(args.certificate, 'rb') as f:
#     cert = x509.load_pem_x509_certificate(f.read(), default_backend())
# print(cert.subject.rdns[0])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((args.host_address, args.host_port))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        print(str(addr) + " connected")
        pubkey = conn.recv(2048).decode()
        print(pubkey)
