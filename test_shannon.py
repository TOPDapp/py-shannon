#  Copyright (c) Kuba Szczodrzyński 2021-5-5.

import pytest

from shannon import Shannon

KEY = b"\x65\x87\xd8\x8f\x6c\x32\x9d\x8a\xe4\x6b"


@pytest.mark.parametrize(
    ["message", "exp_encrypted", "exp_mac"],
    [
        (
            b"Hello World",
            b"\x94\x81\xe5\xa9\x5f\x93\x5e\xcb\x6c\xb5\x24",
            b"\x43\x23\x86\x24\xf3\xc9\x0c\x58\x79\xf4\xd3\xef\x83\x98\x2e\x4e",
        )
    ],
)
def test_encrypt(message: bytes, exp_encrypted: bytes, exp_mac: bytes):
    shannon = Shannon(KEY)

    encrypted = shannon.encrypt(message)
    mac = shannon.finish()

    assert encrypted == exp_encrypted
    assert mac == exp_mac


@pytest.mark.parametrize(
    ["encrypted", "exp_decrypted", "exp_mac"],
    [
        (
            b"\x94\x81\xe5\xa9\x5f\x93\x5e\xcb\x6c\xb5\x24",
            b"Hello World",
            b"\x43\x23\x86\x24\xf3\xc9\x0c\x58\x79\xf4\xd3\xef\x83\x98\x2e\x4e",
        )
    ],
)
def test_decrypt(encrypted: bytes, exp_decrypted: bytes, exp_mac: bytes):
    shannon = Shannon(KEY)

    decrypted = shannon.decrypt(encrypted)
    mac = shannon.finish()

    assert decrypted == exp_decrypted
    assert mac == exp_mac
