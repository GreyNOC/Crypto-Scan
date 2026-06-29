import hashlib
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec

def make_keys():
    rsa_key = RSA.generate(2048)            # quantum-vulnerable (Shor)
    ec_key = ec.generate_private_key(ec.SECP256R1())  # ECDSA, Shor
    return rsa_key, ec_key

def legacy_hash(data):
    return hashlib.md5(data).hexdigest()    # classically broken

def token_hash(data):
    return hashlib.sha256(data).hexdigest() # safe
