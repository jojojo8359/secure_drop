from Crypto.Cipher import AES
from Crypto.Hash import SHA3_256, SHA512
import Crypto.Random


def id_hash(email: str) -> str:
    """Creates an ID hash (hex) from an email string"""
    id_hash_ = SHA3_256.new()
    id_hash_.update(bytearray(email, "utf-8"))
    return id_hash_.hexdigest()


def get_salt() -> bytes:
    """Get a random 32-byte salt value"""
    return Crypto.Random.get_random_bytes(32)


def pass_salt_and_hash(password: str, salt: bytes) -> str:
    """Salt and hash a password"""
    pass_hash = SHA512.new(truncate="256")
    pass_hash.update(bytearray(password, "utf-8"))
    pass_hash.update(salt)
    return pass_hash.hexdigest()


def user_contact_hash(email: str, password: str, salt: bytes) -> str:
    """Get the user/contact hash"""
    pass_hash = SHA512.new(truncate="256")
    pass_hash.update(bytearray(email, "utf-8"))
    pass_hash.update(bytearray(password, "utf-8"))
    pass_hash.update(salt)
    return pass_hash.hexdigest()


def encrypt(plaintext: str, key: str) -> tuple[bytes, bytes]:
    """Encrypt using AES and a 256-bit key. String version of the AES encryption functions."""
    return encrypt_b(plaintext.encode("utf-8"), bytes.fromhex(key))

def encrypt_b(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt using AES and a 256-bit key. Bytes version of the AES encryption functions."""
    cipher_aes = AES.new(key, AES.MODE_SIV)
    return cipher_aes.encrypt_and_digest(data)

def decrypt(ciphertext: bytes, tag: bytes, key: str) -> str:
    """Decrypt using AES and a 256-bit key. String version of the AES decryption functions."""
    return decrypt_b(ciphertext, tag, bytes.fromhex(key)).decode("utf-8")

def decrypt_b(ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
    """Decrypt using AES and a 256-bit key. Bytes version of the AES decryption functions."""
    cipher_aes = AES.new(key, AES.MODE_SIV)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)
