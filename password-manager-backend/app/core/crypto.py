import base64
import json
import os
from fastapi import  HTTPException
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import logging

# Инициализация логера
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

SECRET_PHRASE = os.getenv("SECRET_PHRASE", "My-very-very_secret_phrase")


def derive_key(secret_phrase: str, salt: bytes) -> bytes:
    """Создаёт симметричный ключ из секретной фразы и соли."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(secret_phrase.encode())

def encrypt_master_password(master_password: str, secret_phrase: str = SECRET_PHRASE):
    """Шифрует мастер-пароль."""
    salt = os.urandom(16)
    key = derive_key(secret_phrase, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, master_password.encode(), None)
    encrypted_data = {"ciphertext": base64.b64encode(ciphertext).decode(),
                      "nonce": base64.b64encode(nonce).decode(),
                      "salt": base64.b64encode(salt).decode()}
    return json.dumps(encrypted_data)

def decrypt_master_password(encrypted_data: dict, secret_phrase: str = SECRET_PHRASE):
    """Расшифровывает мастер-пароль."""
    salt = encrypted_data["salt"]
    nonce = encrypted_data["nonce"]
    ciphertext = encrypted_data["ciphertext"]
    key = derive_key(secret_phrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

def encrypt_data(data: str, master_password: str) -> str:
    # Generate a 256-bit key from the master password
    if data is None:
        data = ""
    key = sha256(master_password.encode('utf-8')).digest()

    # Generate a random nonce (12 bytes)
    nonce = os.urandom(12)

    # Create an AES-GCM cipher object
    aesgcm = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()

    # Encrypt the data
    encrypted_data = aesgcm.update(data.encode()) + aesgcm.finalize()

    # Concatenate nonce and encrypted data
    encrypted_data_with_nonce = nonce + encrypted_data + aesgcm.tag

    # Base64 encode the result
    return base64.b64encode(encrypted_data_with_nonce).decode('utf-8')


def decrypt_data(encrypted_data: str, master_password: str) -> str:
    try:
        # Decode the base64 encoded string

        try:
            encrypted_data = fix_padding(encrypted_data)
            encrypted_data_bytes = base64.b64decode(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to decode Base64 string: {encrypted_data}, Error: {e}")
            raise HTTPException(status_code=400, detail="Invalid encrypted data format")

        # Extract nonce, ciphertext, and tag
        nonce = encrypted_data_bytes[:12]
        tag = encrypted_data_bytes[-16:]  # Last 16 bytes are the tag
        ciphertext = encrypted_data_bytes[12:-16]  # Middle part is the ciphertext

        # Generate the same 256-bit key from the master password
        key = sha256(master_password.encode('utf-8')).digest()

        # Create an AES-GCM cipher object for decryption
        aesgcm = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()

        # Decrypt the data
        decrypted_data = aesgcm.update(ciphertext) + aesgcm.finalize()

        return decrypted_data.decode('utf-8')

    except InvalidTag:
        logger.error("Decryption failed: Invalid tag encountered.")
        raise HTTPException(status_code=500, detail="Decryption failed due to Invalid Tag")

    # except Exception as e:
    #     logger.error(f"Error during decryption: {e}")
    #     raise HTTPException(status_code=500, detail="Decryption failed")

def fix_padding(base64_str: str) -> str:
    missing_padding = len(base64_str) % 4
    if missing_padding:
        base64_str += '=' * (4 - missing_padding)
    return base64_str