from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

def rsa_encrypt_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    return encrypted_aes_key

def rsa_decrypt_key(encrypted_aes_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    return aes_key

def hybrid_encryption_demo():
    private_key, public_key = generate_rsa_key_pair()

    aes_key = get_random_bytes(32)

    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)

    data = b"Hello, this is a demo"

    nonce, ciphertext, tag = aes_encrypt(data, aes_key)
    print(f"Ciphertext: {ciphertext.hex()}")

    decrypted_aes_key = rsa_decrypt_key(encrypted_aes_key, private_key)

    decrypted_data = aes_decrypt(nonce, ciphertext, tag, decrypted_aes_key)
    print(f"Decrypted Data: {decrypted_data.decode()}")

if __name__ == "__main__":
    hybrid_encryption_demo()
