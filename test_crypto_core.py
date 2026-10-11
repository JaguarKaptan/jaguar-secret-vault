import pytest
import crypto_core as core
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

PAYLOAD_CASES = [
    pytest.param("report.pdf", 1.5, b"hello, world!", b'\x00${"name": "report.pdf", "mtime": 1.5}hello, world!',id="Standard"),
    pytest.param("şifre.txt", 0.0, b"", b'\x00({"name": "\\u015fifre.txt", "mtime": 0.0}', id="turkish_empty"),
    pytest.param("a b.tar.gz", 1_600_000_000.25, bytes(range(256)), b'\x00.{"name": "a b.tar.gz", "mtime": 1600000000.25}\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' ,id="whole_bytes"),
    pytest.param("x" * 100, 1.5, b"\x00\x01", b'\x00~{"name": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "mtime": 1.5}\x00\x01', id="long_name"),
]

FIXED_SALT = b'c\xd4\xac\xf6\x8cAH\x19K\x92\x1d\xc1\x9b\xc4\xc0\x8c'
FIXED_SALT_2 = b';\x0e\x872)\xe2\x8d\xd1\xfe5\xd1\x02\xa1L8\xa9'
PASSWORD = b'test-password123321'
PASSWORD_2 = B'TEST-PASSWORD-2'
VERSION = 1
VERSION_2 = 2
KNOWN_ANSWER_1 = b'jyluEwp2A55s1CSlMUfyE23c86XmrTIofcRBpJtAGQ4='



# out = core.encrypt_bytes(b"SECRET-DATA", b"secret-password", "note.txt", 1700000000.0)
# print(out.hex())

SECRET_DATA = b'SECRET-DATA'
SECRET_FILE_NAME = "note.txt"
SECRET_MTIME = 1700000000.0
SECRET_PASSWORD = b'secret-password'
SECRET = bytes.fromhex("8a91c2015700e6551de1ad323bfa35bf741c53a980000000006acc0594b2f56f9610a30f39186027e15d8cda9c769f4820d0871746d3cc20e38a7645d9ee8716eaeb6ef4c0f2beba9d134ed4480dc35fcfe73b3e210bbc13305e771adfc17b084dbb447b354a63c978b70d26da40f8d33c73578063ac11a56a700f429dbb2e3a514f966ce88729d18577dddb00")



# ----------------------------------------- #
#               PAYLOAD TESTS               #
# ----------------------------------------- #

@pytest.mark.parametrize("name, mtime, data, expected", PAYLOAD_CASES)
def test_build_payload_known_bytes(name, mtime, data, expected):
    payload = core.build_payload(name, mtime, data)

    assert payload == expected


@pytest.mark.parametrize("name, mtime, data, expected", PAYLOAD_CASES)
def test_parse_payload_known_bytes(name, mtime, data, expected):
    payload = expected
    metadata, raw_data = core.parse_payload(payload)
    assert metadata == {"name": name, "mtime": mtime}
    assert raw_data == data


def test_parse_payload_inappropriate_length():
    payload_2 = b'\x00${"name": "report.pdf", "mtime": 0}hello, world!'
    with pytest.raises(ValueError):
        core.parse_payload(payload_2)

    payload_3 = b'\x00\x22{"name": "report.pdf", "mtime": 1.5}hello, world!'
    with pytest.raises(ValueError):
        core.parse_payload(payload_3)


@pytest.mark.parametrize("name, mtime, data, expected", PAYLOAD_CASES)
def test_payload_roundtrip(name, mtime, data, expected):
    payload = core.build_payload(name, mtime, data)
    metadata, parsed_data = core.parse_payload(payload)

    assert metadata["name"] == name
    assert metadata["mtime"] == mtime
    assert parsed_data == data


# ----------------------------------------- #
#            KEY DERIVITION TESTS           #
# ----------------------------------------- #


def test_deterministic_behaviour():
    assert core._derive_key(PASSWORD,FIXED_SALT,VERSION) == core._derive_key(PASSWORD,FIXED_SALT,VERSION)

def test_different_password():
    assert core._derive_key(PASSWORD,FIXED_SALT,VERSION) != core._derive_key(PASSWORD_2,FIXED_SALT,VERSION)

def test_different_salt():
    assert core._derive_key(PASSWORD,FIXED_SALT,VERSION) != core._derive_key(PASSWORD,FIXED_SALT_2,VERSION)

def test_different_version(monkeypatch):
    p = core.KDF_PARAMS[VERSION]
    monkeypatch.setitem(core.KDF_PARAMS, VERSION_2, {**p, "time_cost": p["time_cost"] + 1})
    assert core._derive_key(PASSWORD, FIXED_SALT, VERSION) != core._derive_key(PASSWORD, FIXED_SALT, 2)

def test_key_length():
    key = core._derive_key(PASSWORD, FIXED_SALT, VERSION)
    assert len(b64d(key)) == 32

def test_unsupported_version():
    with pytest.raises(ValueError):
        core._derive_key(PASSWORD, FIXED_SALT, 555)

def test_known_answer():
    assert core._derive_key(PASSWORD, FIXED_SALT, VERSION) == KNOWN_ANSWER_1


# ----------------------------------------- #
#            ENCRYPTION TESTS               #
# ----------------------------------------- #

def test_encrypt_header_layout():
    out = core.encrypt_bytes(b"abc", PASSWORD, "a.txt", 1.0)
    assert out[:3] == b'\x8a\x91\xc2'      
    assert out[3] == 1            
    assert len(out) > 3 + 1 + 16  

def test_encrypt_is_random():
    a = core.encrypt_bytes(b"abc", PASSWORD, "a.txt", 1.0)
    b = core.encrypt_bytes(b"abc", PASSWORD, "a.txt", 1.0)
    assert a != b  

def test_encrypt_hides_plaintext():
    out = core.encrypt_bytes(b"SUPER-SECRET-SYMBOL", PASSWORD, "document.txt", 1.0)
    assert b"SUPER-SECRET-SYMBOL" not in out
    assert b"document" not in out 

def test_encrypt_rejects_double_encryption():
    once = core.encrypt_bytes(b"abc", PASSWORD, "a.txt", 1.0)
    with pytest.raises(ValueError):
        core.encrypt_bytes(once, PASSWORD, "a.txt", 1.0)
    with pytest.raises(ValueError):
        core.encrypt_bytes(b"abc", PASSWORD, "a" + ".jsv", 1.0)



# ----------------------------------------- #
#            DECRYPTION TESTS               #
# ----------------------------------------- #

def test_decrypt_secret():
    meta, data = core.decrypt_bytes(SECRET, SECRET_PASSWORD)
    assert data == b"SECRET-DATA"
    assert meta["name"] == "note.txt"
    assert meta["mtime"] == 1700000000.0

def test_decrypt_wrong_password():
    with pytest.raises(ValueError):
        core.decrypt_bytes(SECRET, b"wrong-password")

def test_decrypt_too_short():
    with pytest.raises(ValueError):
        core.decrypt_bytes(b"abc", SECRET_PASSWORD)

def test_decrypt_header_only():
    with pytest.raises(ValueError):
        core.decrypt_bytes(SECRET[:20], SECRET_PASSWORD)  

def test_decrypt_truncated():
    with pytest.raises(ValueError):
        core.decrypt_bytes(SECRET[:-1], SECRET_PASSWORD)  

@pytest.mark.parametrize("pos", [0, 3, 5, 20, len(SECRET) // 2, -1])  # magic, version, SALT, Fernet_title, ciphertext middle, HMAC END
def test_decrypt_tampered(pos):
    blob = bytearray(SECRET)
    blob[pos] ^= 0x01 
    with pytest.raises(ValueError):
        core.decrypt_bytes(bytes(blob), SECRET_PASSWORD)


# ----------------------------------------- #
#            ENC-DEC-CYCLE TESTS            #
# ----------------------------------------- #

@pytest.mark.parametrize("name, mtime, data, expected", PAYLOAD_CASES)
def test_encrypt_decrypt_roundtrip(name, mtime, data, expected):
    encrypted_data = core.encrypt_bytes(data,PASSWORD, name, mtime)
    metadata, raw_data = core.decrypt_bytes(encrypted_data, PASSWORD)

    assert raw_data == data
    assert metadata["name"] == name
    assert metadata["mtime"] == mtime

# ----------------------------------------- #
#                FILE TESTS                 #
# ----------------------------------------- #


