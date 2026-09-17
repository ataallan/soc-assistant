from nlp_utils import extract_ip, extract_user


def test_extract_ip():
    assert extract_ip("connection from 192.168.1.20 refused") == "192.168.1.20"


def test_extract_user():
    assert extract_user("auth failure user=bob service=ssh") == "bob"


def test_extract_missing():
    assert extract_ip("no address here") is None
    assert extract_user("no user field") is None
