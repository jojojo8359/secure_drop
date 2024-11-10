from Crypto.Hash import SHA3_256, SHA512
import Crypto.Random

# Creates an ID hash (hex) from an email string
def id_hash(email: str) -> str:
    id_hash = SHA3_256.new()
    id_hash.update(bytearray(email, "utf-8"))
    return id_hash.hexdigest()

# Get a random 32-byte salt value
def get_salt() -> bytes:
    return Crypto.Random.get_random_bytes(32)

# Salt and hash a password
def pass_salt_and_hash(password: str, salt: bytes) -> str:
    pass_hash = SHA512.new(truncate="256")
    pass_hash.update(bytearray(password, "utf-8"))
    pass_hash.update(salt)
    return pass_hash.hexdigest()
