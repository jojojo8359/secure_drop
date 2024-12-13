from ca import build_csr, sign_csr, validate_cert
from ecdh import ec_gen_private_key, get_shared_key, ec_sign, ec_verify, ec_pub_key_to_bytes, ec_bytes_to_pub_key
import sys

U_email = "foo1@foo.com"
V_email = "foo2@foo.com"

# U runs
U_signing = ec_gen_private_key()
U_csr = build_csr(U_signing, U_email)
U_cert = sign_csr(U_csr)
if U_cert == None:
    print("Couldn't generate a certificate for client U")
    sys.exit(1)
if not validate_cert(U_cert, U_email):
    print("Couldn't validate certificate for client U")
    sys.exit(1)

U_data = ec_gen_private_key()
U_data_pub_bytes: bytes = ec_pub_key_to_bytes(U_data.public_key())
U_data_pub_sig: bytes = ec_sign(U_signing, U_data_pub_bytes)

# V runs
V_signing = ec_gen_private_key()
V_csr = build_csr(V_signing, V_email)
V_cert = sign_csr(V_csr)
if V_cert == None:
    print("Couldn't generate a certificate for client V")
    sys.exit(1)
if not validate_cert(V_cert, V_email):
    print("Couldn't validate certificate for client V")
    sys.exit(1)

V_data = ec_gen_private_key()
V_data_pub_bytes: bytes = ec_pub_key_to_bytes(V_data.public_key())
V_data_pub_sig: bytes = ec_sign(V_signing, V_data_pub_bytes)

# HANDSHAKE
# U sends V its certificate, as well as its public data key signed with its identity private key
# V sends U its certificate, as well as its public data key signed with its identity private key
# U can see V_cert, V_data_pub, V_data_pub_sig
# V can see U_cert, U_data_pub, U_data_pub_sig


# U runs
# Verify that the certificate it got matches its expectation
# V_email = "foo3@foo.com"
if not validate_cert(V_cert, V_email):
    print("Client U couldn't validate the identity of client V")
    sys.exit(1)
V_pub_signing = V_cert.public_key()
if not ec_verify(V_pub_signing, V_data_pub_sig, V_data_pub_bytes):
    print("Client U couldn't verify the public data key of client V")
    sys.exit(1)
V_data_pub = ec_bytes_to_pub_key(V_data_pub_bytes)
if V_data_pub == None:
    print("Couldn't convert bytes to EC public key.")
    sys.exit(1)
U_shared_data_key = get_shared_key(U_data, V_data_pub)



# V runs
# Verify that the certificate it got matches its expectation
if not validate_cert(U_cert, U_email):
    print("Client V couldn't validate the identity of client U")
    sys.exit(1)
U_pub_signing = U_cert.public_key()
if not ec_verify(U_pub_signing, U_data_pub_sig, U_data_pub_bytes):
    print("Client V couldn't verify the public data key of client U")
    sys.exit(1)
U_data_pub = ec_bytes_to_pub_key(U_data_pub_bytes)
if U_data_pub == None:
    print("Couldn't convert bytes to EC public key.")
    sys.exit(1)
V_shared_data_key = get_shared_key(V_data, U_data_pub)


print("U's data key: " + bytes.hex(U_shared_data_key))
print("V's data key: " + bytes.hex(V_shared_data_key))
