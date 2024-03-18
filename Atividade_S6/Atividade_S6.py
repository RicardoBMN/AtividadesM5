import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time

# Função para calcular o hash SHA-256 de uma mensagem
def sha256_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

# Função para criptografar uma mensagem usando AES-256
def aes256_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return (ciphertext, cipher.nonce, tag)

# Função para descriptografar uma mensagem usando AES-256
def aes256_decrypt(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()

# Mensagens de teste e chave AES
messages = [
    "Hello, world!",
    "Python is awesome",
    "Cryptography is fun",
    "This is a test message",
    "Hashing and encryption",
    "Secure communication",
    "Message authentication",
    "Data integrity",
    "Confidentiality",
    "Privacy protection"
]
aes_key = get_random_bytes(32)  # 256-bit chave

# Tabela de resultados
print("Teste | SHA-256 Hash | AES-256 Encryption | AES-256 Decryption | Tempo SHA-256 | Tempo AES-256")
print("-" * 95)

# Realizar testes
for i, message in enumerate(messages, start=1):
    start_time_sha = time.time()
    sha_hash = sha256_hash(message)
    end_time_sha = time.time()

    start_time_aes = time.time()
    encrypted, nonce, tag = aes256_encrypt(message, aes_key)
    decrypted = aes256_decrypt(encrypted, nonce, tag, aes_key)
    end_time_aes = time.time()

    print(f"{i:<5} | {sha_hash} | {encrypted} | {decrypted} | {end_time_sha - start_time_sha:.6f} | {end_time_aes - start_time_aes:.6f}")
