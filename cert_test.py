from ca import build_csr, sign_csr, validate_cert
from ecdh import *
from cryptography.hazmat.primitives import serialization
from cryptography import x509

key = ec_gen_private_key()

email = "foo1@foo.com"

csr = build_csr(key, email)
# print(csr.public_bytes(serialization.Encoding.PEM))
cert = sign_csr(csr)
if cert != None:
    print(cert.public_bytes(serialization.Encoding.PEM))

# with open("client.cert", "rb") as f:
#     cert_pem = f.read()
# cert = x509.load_pem_x509_certificate(cert_pem)

valid = validate_cert(cert, email)
print("Certificate valid: " + str(valid))
