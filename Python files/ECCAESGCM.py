from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from os import urandom

def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    return derived_key

def aes_encrypt(data, key):
    iv = urandom(12) 
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    padded_data = PKCS7(128).padder().update(data) + PKCS7(128).padder().finalize()
    ciphertext, tag = encryptor.update(padded_data) + encryptor.finalize(), encryptor.tag
    return iv, ciphertext, tag

def aes_decrypt(iv, ciphertext, tag, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

def hybrid_encryption_demo():
    private_key_ecc_device1, public_key_ecc_device1 = generate_ecc_key_pair()
    private_key_ecc_device2, public_key_ecc_device2 = generate_ecc_key_pair()

    shared_key_device1 = derive_shared_key(private_key_ecc_device1, public_key_ecc_device2)
    shared_key_device2 = derive_shared_key(private_key_ecc_device2, public_key_ecc_device1)
    assert shared_key_device1 == shared_key_device2, "Key derivation mismatch!"
    
    data = b"Hello, this is a demo"
    iv, ciphertext, tag = aes_encrypt(data, shared_key_device1)
    print(f"Ciphertext: {ciphertext.hex()}")

    decrypted_data = aes_decrypt(iv, ciphertext, tag, shared_key_device2)
    print(f"Decrypted Data: {decrypted_data.decode()}")

if __name__ == "__main__":
    hybrid_encryption_demo()
