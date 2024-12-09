import socket
import ssl
import argparse

# RECEIVER
parser = argparse.ArgumentParser(prog="tcp_client", description="Receive files with encryption and authentication")
parser.add_argument('host_address', type=str, help='IP Address of the server to connect to')
parser.add_argument('host_port', type=int, help='Port number of the server to connect to')
parser.add_argument('key', type=str, help='File with client\'s private key')
parser.add_argument('certificate', type=str, help='File with client\'s certificate')
parser.add_argument('email', type=str, help='The user\'s email')
args = parser.parse_args()

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile='ca.cert.pem')
context.load_cert_chain(certfile=args.certificate, keyfile=args.key)
# context.load_cert_chain(certfile='ca.cert.pem', keyfile='ca.key.pem')

with socket.create_connection((args.host_address, args.host_port)) as sock:
    with context.wrap_socket(sock, server_side=False, server_hostname='client1@foo.com') as ssock:
        print(ssock.version())
        # prepare to transfer
        # receiver pub/priv keys should be created if not already
        
        # receiver sends sender: public key
        with open(args.key, 'r') as f:
            keydata = f.read()
        ssock.send(keydata.encode())
        # wait for ack
        # receiver sends sender: certificate
        # wait for auth ack
        # authenticated


