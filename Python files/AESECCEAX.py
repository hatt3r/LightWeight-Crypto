from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
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
    iv = urandom(16) 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv, encrypted_data

def aes_decrypt(encrypted_data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = PKCS7(128).unpadder()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
    return decrypted_data


def hybrid_encryption_demo():
    private_key_device1, public_key_device1 = generate_ecc_key_pair()
    private_key_device2, public_key_device2 = generate_ecc_key_pair()
    
    shared_key_device1 = derive_shared_key(private_key_device1, public_key_device2)
    shared_key_device2 = derive_shared_key(private_key_device2, public_key_device1)
    
    assert shared_key_device1 == shared_key_device2, "Key derivation mismatch!"
    
    data = b"Hello, this is a demo"
    iv, encrypted_data = aes_encrypt(data, shared_key_device1)
    print(f"Encrypted Data: {encrypted_data.hex()}")
    
    decrypted_data = aes_decrypt(encrypted_data, shared_key_device2, iv)
    print(f"Decrypted Data: {decrypted_data.decode()}")

if __name__ == "__main__":
    hybrid_encryption_demo()
