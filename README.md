# py-shannon

[![PyPI](https://img.shields.io/pypi/v/py-shannon?style=for-the-badge)](https://pypi.org/project/py-shannon/)

Pure Python implementation of Shannon stream cipher. No-brainer port of [shannon](https://github.com/twonky4/shannon).

Shannon cipher is used in Spotify Connect to encrypt communication between player and Spotify AP server. Shannon cipher
is variant of [Sober](https://en.wikipedia.org/wiki/SOBER) stream cipher.

## Example
Encryption
```python
from shannon import Shannon

key = b"\x65\x87\xd8\x8f\x6c\x32\x9d\x8a\xe4\x6b"
message = "My secret message".encode("utf-8")

shannon = Shannon(key)

message = shannon.encrypt(message)  # -> bytes
# message contains ciphertext now
mac = shannon.finish()  # -> bytes
# mac contains MAC of the message
```

Decryption
```python
from shannon import Shannon

key = b"\x65\x87\xd8\x8f\x6c\x32\x9d\x8a\xe4\x6b"
# message is encrypted
message = b"\x91\x9d\xa9\xb6\x29\xfc\x9c\xdd\x17\x8c\x15\x31\x9a\xae\xcc\x6e\xd4"
received_mac = b"\xbe\x7b\xef\x39\xee\xfe\x54\xfd\x8d\xb0\xbc\x6f\xd5\x30\x35\x19"

shannon = Shannon(key)
message = shannon.decrypt(message)  # -> bytes
# message contains plaintext now
mac = shannon.finish()
if mac == received_mac:
    print("MAC OK")
```
