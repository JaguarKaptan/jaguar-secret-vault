import pytest
import crypto_core as core

PAYLOAD_CASES = [
    pytest.param("report.pdf", 1.5, b"hello, world!", b'\x00${"name": "report.pdf", "mtime": 1.5}hello, world!',id="Standard"),
    pytest.param("şifre.txt", 0.0, b"", b'\x00({"name": "\\u015fifre.txt", "mtime": 0.0}', id="turkish_empty"),
    pytest.param("a b.tar.gz", 1_600_000_000.25, bytes(range(256)), b'\x00.{"name": "a b.tar.gz", "mtime": 1600000000.25}\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' ,id="whole_bytes"),
    pytest.param("x" * 100, 1.5, b"\x00\x01", b'\x00~{"name": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "mtime": 1.5}\x00\x01', id="long_name"),
]


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

    payload_2 = b'\x00${"name": "report.pdf", "mtime": 0}hello, world!'
    with pytest.raises(ValueError):
        core.parse_payload(payload_2)

    payload_3 = b'\x00\x22{"name": "report.pdf", "mtime": 1.5}hello, world!'
    with pytest.raises(ValueError):
        core.parse_payload(payload_3)





# @pytest.mark.parametrize("name, mtime, data", [
#     ("report.pdf", 1.5, b"hello, world!"),
#     ("şifre.txt", 0.0, b""),                                  # Turkish name, empty file
#     ("a b.tar.gz", 1_600_000_000.25, bytes(range(256))),      # Each bytes value
#     ("x" * 200, 1.5, b"\x00\x01"),                            # Long name
# ])
@pytest.mark.parametrize("name, mtime, data, expected", PAYLOAD_CASES)
def test_payload_roundtrip(name, mtime, data, expected):
    payload = core.build_payload(name, mtime, data)
    metadata, parsed_data = core.parse_payload(payload)

    assert metadata["name"] == name
    assert metadata["mtime"] == mtime
    assert parsed_data == data

