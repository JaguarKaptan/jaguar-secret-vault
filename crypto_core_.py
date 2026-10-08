from base64 import urlsafe_b64encode as b64e
from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
import secrets, os, json

MAGIC_BYTES = b'\x8a\x91\xc2' #b'\x4a\x53\x56' -> JSV
KDF_PARAMS = {1: {"time_cost": 3, "memory_cost": 102400, "parallelism": 8}}


def build_payload(name: str, mtime: float, data: bytes) -> bytes:
    """Build a payload with metadata and data"""
    metadata = {
        "name": name,
        "mtime": mtime
    }
    header = json.dumps(metadata).encode()

    return len(header).to_bytes(2, "big") + header + data

def parse_payload(payload: bytes) -> tuple[dict, bytes]:
    """Parse a payload into metadata and data"""
    n = int.from_bytes(payload[:2], "big")
    json_data = payload[2:n+2]
    data = payload[n+2:]

    metadata = json.loads(json_data.decode())
    return metadata, data

def _derive_key(password: bytes, salt: bytes, version: int) -> bytes:

    if version not in KDF_PARAMS:
        raise ValueError(f"Unsupported KDF version: {version}")
    params = KDF_PARAMS[version]

    """Derive a secret key from a given password and salt"""
    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=32,
        type=Type.ID
    )
    return b64e(key)

def encrypt_bytes(data: bytes, password: bytes) -> bytes:
    salt = secrets.token_bytes(16)

    key= _derive_key(password, salt, version=1)

    ciphertext = Fernet(key).encrypt(data)

    return salt + ciphertext

def decrypt_bytes(encrypted_data: bytes, password: bytes) -> bytes:
    salt = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    key = _derive_key(password, salt, version=1)
    try:
        decrypted_data = Fernet(key).decrypt(ciphertext)
        return decrypted_data
    except InvalidToken:
        raise ValueError("Invalid password or corrupted data")


def process_file(file_path: str, password: str, mode: str = "encrypt"):
    with open(file_path, "rb") as f:
        raw_data = f.read()

    match mode:
        case "encrypt":
            process_data = encrypt_bytes(raw_data, password.encode())
            output_file = file_path.replace(".txt", "_encrypted.txt")
        case "decrypt":
            process_data = decrypt_bytes(raw_data, password.encode())
            output_file = file_path
        case _:
            raise ValueError("Invalid mode. Use 'encrypt' or 'decrypt'.")
        
    # if mode == "encrypt":
    #     process_data = encrypt_bytes(raw_data, password.encode())
    #     output_file = file_path.replace(".txt", "_encrypted.txt")
    # elif mode == "decrypt":
    #     process_data = decrypt_bytes(raw_data, password.encode())
    #     output_file = file_path

    #Atomic write and read
    temp_path = output_file + '.tmp'
    try:
        with open(temp_path, "wb") as temp_file:
            temp_file.write(process_data)
        os.replace(temp_path, output_file)
        os.rename(output_file, output_file.replace("encrypted.txt", "_.txt") if mode == "decrypt" else output_file)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e


#Tests
file_path = "test_file.txt"
file_path2 = "test_file_encrypted.txt"
process_file(file_path2, "1234", mode="decrypt")

# with open(file_path, "rb") as f:
#     binary_data = f.read()
#     print("Read raw data: ", binary_data)
#     print("Data Type: ", type(binary_data))

# enrypted_data = encrypt_bytes(binary_data, "1234")

# with open("encrypted_file.txt", "wb") as f:
#     f.write(enrypted_data)
#     print("Encrypted data written to file.")


# decrypted_data = decrypt_bytes(enrypted_data, "1234")

# with open("decrypted_file.txt", "wb") as f:
#     f.write(decrypted_data)
#     print("Decrypted data written to file.")
