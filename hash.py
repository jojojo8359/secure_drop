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
