from dh import DiffieHellman

dh1 = DiffieHellman()
pub1 = dh1.get_public_key()
print("Public key 1: " + str(pub1))

dh2 = DiffieHellman()
pub2 = dh2.get_public_key()
print("Public key 2: " + str(pub2))

priv1 = dh1.get_private_key(pub2)
priv2 = dh2.get_private_key(pub1)

print("Private key 1: " + str(priv1))
print("Private key 2: " + str(priv2))
print("Private keys equal: " + str(priv1 == priv2))
