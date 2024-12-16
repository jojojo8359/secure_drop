from typing import Union
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def ec_gen_private_key() -> ec.EllipticCurvePrivateKey:
    """
    Generate an EC private key.

    Returns the EC private key.
    """
    return ec.generate_private_key(ec.SECP384R1())


def get_shared_key(private_key: ec.EllipticCurvePrivateKey, public_key:
                   ec.EllipticCurvePublicKey) -> bytes:
    """
    Create a shared key from an EC private key and an EC public key.

    Returns the shared key in bytes form.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'iC1qSgq98IPSZ3UqkzN99DVHljbQmwjauCURlsUP4kK6i9g0ddtqxxcNR7n8D3'
             b'c8gna92e7XM6cM2ComsjyMhelgimdbyozWLcFA',
        info=None
    ).derive(private_key.exchange(ec.ECDH(), public_key))


def ec_sign(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """
    Sign data with an EC private key.

    Returns the signature in bytes form.
    """
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def ec_pub_key_to_bytes(pub_key: ec.EllipticCurvePublicKey) -> bytes:
    """
    Convert an EC public key to bytes form. This conversion uses the DER
    encoding format.
    """
    return pub_key.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.
                                SubjectPublicKeyInfo)


def ec_bytes_to_pub_key(b: bytes) -> Union[ec.EllipticCurvePublicKey, None]:
    """
    Convert bytes to an EC public key. This conversion uses the DER encoding
    format.

    If the provided data is not an EC public key, returns None. Otherwise,
    returns the EC public key.
    """
    key = serialization.load_der_public_key(b)
    if isinstance(key, ec.EllipticCurvePublicKey):
        return key
    return None


def ec_verify(key: ec.EllipticCurvePublicKey, signature: bytes,
              data: bytes) -> bool:
    """
    Verify an EC signature, given an EC public key, the data, and the data's
    signature.

    If the data was signed with the EC private key corresponding to the
    provided EC public key, returns True. Otherwise, returns False.
    """
    try:
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("Couldn't verify signature.")
        return False
    return True
