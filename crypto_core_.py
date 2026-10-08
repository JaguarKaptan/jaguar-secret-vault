from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
import secrets, os, json
from enum import Enum

MAGIC_BYTES = b'\x8a\x91\xc2' #b'\x4a\x53\x56' -> JSV
KDF_PARAMS = {1: {"time_cost": 3, "memory_cost": 102400, "parallelism": 8}}
class Mode(Enum):
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"

CURRENT_VERSION = 1

SALT_LEN = 16
VERSION_POS = len(MAGIC_BYTES)
SALT_START_POS = VERSION_POS + 1
TOKEN_START_POS = SALT_START_POS + SALT_LEN

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

    """Derive a secret key from a given password and salt"""

    if version not in KDF_PARAMS:
        raise ValueError(f"Unsupported KDF version: {version}")
    params = KDF_PARAMS[version]


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

def encrypt_bytes(data: bytes, password: bytes, file_name: str, mtime: float) -> bytes:
    salt = secrets.token_bytes(16)

    key= _derive_key(password, salt, version=CURRENT_VERSION)

    payload = build_payload(name=file_name, mtime= mtime, data=data)

    mix = MAGIC_BYTES + bytes([CURRENT_VERSION]) + salt

    ciphertext = Fernet(key).encrypt(payload)
    

    return mix + b64d(ciphertext)

def decrypt_bytes(encrypted_data: bytes, password: bytes) -> tuple[dict, bytes]:

    magic_bytes = encrypted_data[:VERSION_POS]
    #magic_bytes = encrypted_data[:3]

    if magic_bytes != MAGIC_BYTES:
        raise ValueError(f"This is not a .jsv file!")
    
    # version = encrypted_data[3:4]
    # salt = encrypted_data[4:20]
    # ciphertext = encrypted_data[20:]

    version = encrypted_data[VERSION_POS]
    salt = encrypted_data[SALT_START_POS:TOKEN_START_POS]
    ciphertext = encrypted_data[TOKEN_START_POS:]
    
    key = _derive_key(password, salt, version=version)
    try:
        decrypted_data = Fernet(key).decrypt(b64e(ciphertext))
        return parse_payload(decrypted_data)
    except InvalidToken:
        raise ValueError("Invalid password or corrupted data")

    


def process_file(file_path: str, password: str, mode: Mode = Mode.ENCRYPT):

    path_name = Path(file_path)

    if not path_name.exists():                    
            raise FileNotFoundError(f"{file_path} is not exists!")

    file_name=path_name.name
    mtime=path_name.stat().st_mtime


    with open(file_path, "rb") as f:
        raw_data = f.read()

    match mode:
        case Mode.ENCRYPT:
            process_data = encrypt_bytes(raw_data, password.encode(), file_name = file_name, mtime = mtime)
            output_file = path_name.with_name(f"encrypted_{path_name.stem}.jsv")
        case Mode.DECRYPT:
            metadata, process_data = decrypt_bytes(raw_data, password.encode())
            original_file = Path(metadata["name"]).name
            output_file = path_name.with_name(f"{original_file}")

            # orj_file_name = Path(metadata["name"])
            # orj_file_ext = orj_file_name.suffix
            # output_file = orj_file_name.replace(file_ext, f"_decrypted{orj_file_ext}")
            
            #output_file = file_path
        case _:
            raise ValueError("Invalid mode. Use 'encrypt' or 'decrypt'.")

    
    temp_file = prepare_file(output_file=output_file, process_data=process_data)
    overwrite = check_and_prompt(output_file=output_file)

    commit_output(temp_path=temp_file, output_file=output_file, overwrite=overwrite)

    if overwrite and mode == Mode.DECRYPT:
        os.utime(output_file, (metadata["mtime"], metadata["mtime"]))
        path_name.unlink()

def check_and_prompt(output_file: Path) -> bool:
    if output_file.exists():       
        while True:
            prompt = input(f"{output_file} is already exists, would you like to overwrite it? y/n : ")             
            if prompt.lower() == "y":
                return True
            elif prompt.lower() == "n":
                return False
            else:
                continue
    else:
        return True


        #raise FileExistsError(f"{output_file} is already exists!")
    
def commit_output(temp_path: Path, output_file: Path, overwrite: bool) -> None:
    if overwrite:
        try:
            os.replace(temp_path, output_file)
            print("Process Completed!")
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e
    else:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        print("Process Canceled!")

def prepare_file(output_file: Path, process_data: bytes) -> Path:

    temp_path = output_file.with_name(output_file.name + ".tmp")
        
    try:
        with open(temp_path, "wb") as temp_file:
            temp_file.write(process_data)
         
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e

    return temp_path

file_path = "test_file.txt"
file_path2 = "encrypted_test_file.jsv"

password = "1234"
mode = "decrypt"


# blob = encrypt_bytes(b"hi", b"1234", "a.txt", 1.5)
# print(blob[:4])                          # b'\x8a\x91\xc2\x01'
# print(decrypt_bytes(blob, b"1234"))      # ({'name': 'a.txt', 'mtime': 1.5}, b'hi')

if __name__ == "__main__":
    process_file(file_path = file_path2, password=password, mode=Mode.ENCRYPT)

