from nlp_utils import extract_ip, extract_user


def test_extract_ip():
    assert extract_ip("connection from 192.168.1.20 refused") == "192.168.1.20"


def test_extract_user():
    assert extract_user("auth failure user=bob service=ssh") == "bob"


def test_extract_missing():
    assert extract_ip("no address here") is None
    assert extract_user("no user field") is None


def test_extract_user_auth_phrases():
    assert extract_user("Failed password for invalid user admin from 1.2.3.4") == "admin"
    assert extract_user("sshd: Invalid user oracle from 10.0.0.1") == "oracle"
    assert extract_user("Accepted publickey for alice from 10.0.0.2") == "alice"
    assert extract_user("login for user bob.jones succeeded") == "bob.jones"
