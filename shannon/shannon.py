#  Copyright (c) Kuba Szczodrzyński 2021-5-5.

from typing import List, Union

N = 16
FOLD = N
INITKONST = 0x6996C53A
KEYP = 13


def rotate_left(i: int, distance: int) -> int:
    return ((i << distance) | (i >> (32 - distance))) & 0xFFFFFFFF


def sbox(i: int) -> int:
    i ^= rotate_left(i, 5) | rotate_left(i, 7)
    i ^= rotate_left(i, 19) | rotate_left(i, 22)
    return i


def sbox2(i: int) -> int:
    i ^= rotate_left(i, 7) | rotate_left(i, 22)
    i ^= rotate_left(i, 5) | rotate_left(i, 19)
    return i


def shift4(buf: Union[bytes, List[int]], i: int) -> int:
    return (
        ((buf[i + 3] & 0xFF) << 24)
        | ((buf[i + 2] & 0xFF) << 16)
        | ((buf[i + 1] & 0xFF) << 8)
        | (buf[i] & 0xFF)
    )


def pack4(buf: List[int], i: int, word: int):
    buf[i + 3] = (word >> 24) & 0xFF
    buf[i + 2] = (word >> 16) & 0xFF
    buf[i + 1] = (word >> 8) & 0xFF
    buf[i] = word & 0xFF


class Shannon:
    R = [0x00] * N
    CRC = [0x00] * N
    initR = [0x00] * N
    konst = 0
    sbuf = 0
    mbuf = 0
    nbuf = 0

    def _cycle(self) -> None:
        t = self.R[12] ^ self.R[13] ^ self.konst
        t = sbox(t) ^ rotate_left(self.R[0], 1)

        for i in range(1, N):
            self.R[i - 1] = self.R[i]

        self.R[N - 1] = t

        t = sbox2(self.R[2] ^ self.R[15])
        self.R[0] ^= t
        self.sbuf = t ^ self.R[8] ^ self.R[12]

    def _crc(self, i: int) -> None:
        t = self.CRC[0] ^ self.CRC[2] ^ self.CRC[15] ^ i

        for j in range(1, N):
            self.CRC[j - 1] = self.CRC[j]

        self.CRC[N - 1] = t

    def _mac(self, i: int) -> None:
        self._crc(i)

        self.R[KEYP] ^= i

    def _init_state(self) -> None:
        self.R[0] = 1
        self.R[1] = 1

        for i in range(2, N):
            self.R[i] = self.R[i - 1] + self.R[i - 2]

        self.konst = INITKONST

    def _save_state(self) -> None:
        self.initR = list(self.R)

    def _reload_state(self) -> None:
        self.R = list(self.initR)

    def _gen_konst(self) -> None:
        self.konst = self.R[0]

    def _add_key(self, k: int):
        self.R[KEYP] ^= k

    def _diffuse(self):
        for i in range(0, FOLD):
            self._cycle()

    def _load_key(self, key: bytes):
        extra = [0x00] * len(key)
        i = j = 0

        for i in range(0, len(key) & ~0x03, 4):
            t = shift4(key, i)
            self._add_key(t)
            self._cycle()
        i += 4

        if i < len(key):
            while i < len(key):
                extra[j] = key[i]
                i += 1
                j += 1

            while j < 4:
                extra[j] = 0x00
                j += 1

            t = shift4(extra, 0)
            self._add_key(t)
            self._cycle()

        self._add_key(len(key))
        self._cycle()
        self.CRC = list(self.R)
        self._diffuse()

        for i in range(0, N):
            self.R[i] ^= self.CRC[i]

    def set_key(self, key: bytes):
        self._init_state()
        self._load_key(key)
        self._gen_konst()
        self._save_state()
        self.nbuf = 0

    def set_nonce(self, nonce: bytes):
        self._reload_state()
        self.konst = INITKONST
        self._load_key(nonce)
        self._gen_konst()
        self.nbuf = 0

    def _stream(self, buf: bytes) -> bytes:
        buf = list(buf)
        i = 0
        n = len(buf)

        while self.nbuf != 0 and n != 0:
            buf[i] ^= self.sbuf & 0xFF
            i += 1
            self.sbuf >>= 8
            self.nbuf -= 8
            n -= 1

        j = n & ~0x03

        while i < j:
            self._cycle()
            pack4(buf, i, self.sbuf)

        n &= 0x03

        if n != 0:
            self._cycle()
            self.nbuf = 32

            while self.nbuf != 0 and n != 0:
                buf[i] ^= self.sbuf & 0xFF
                i += 1
                self.sbuf >>= 8
                self.nbuf -= 8
                n -= 1

        return bytes(buf)

    def _mac_only(self, buf: bytes) -> bytes:
        buf = list(buf)
        i = 0
        n = len(buf)

        if self.nbuf != 0:
            while self.nbuf != 0 and n != 0:
                self.mbuf ^= buf[i] << (32 - self.nbuf)
                i += 1
                self.nbuf -= 8
                n -= 1

            if self.nbuf != 0:
                return bytes(buf)

            self._mac(self.mbuf)

        j = n & ~0x03

        while i < j:
            self._cycle()
            t = shift4(buf, i)
            self._mac(t)
            i += 4

        n &= 0x03

        if n != 0:
            self._cycle()
            self.mbuf = 0
            self.nbuf = 32

            while self.nbuf != 0 and n != 0:
                self.mbuf ^= buf[i] << (32 - self.nbuf)
                i += 1
                self.nbuf -= 8
                n -= 1

        return bytes(buf)

    # noinspection DuplicatedCode
    def encrypt(self, buf: bytes, length: int = None) -> bytes:
        buf = list(buf)
        n = length or len(buf)
        i = 0

        if self.nbuf != 0:
            while self.nbuf != 0 and n != 0:
                self.mbuf ^= (buf[i] & 0xFF) << (32 - self.nbuf)
                buf[i] ^= (self.sbuf >> (32 - self.nbuf)) & 0xFF
                i += 1
                self.nbuf -= 8
                n -= 1

            if self.nbuf != 0:
                return bytes(buf)

            self._mac(self.mbuf)

        j = n & ~0x03

        while i < j:
            self._cycle()
            t = shift4(buf, i)
            self._mac(t)
            t ^= self.sbuf
            pack4(buf, i, t)
            i += 4

        n &= 0x03

        if n != 0:
            self._cycle()
            self.mbuf = 0
            self.nbuf = 32

            while self.nbuf != 0 and n != 0:
                self.mbuf ^= (buf[i] & 0xFF) << (32 - self.nbuf)
                buf[i] ^= (self.sbuf >> (32 - self.nbuf)) & 0xFF
                i += 1
                self.nbuf -= 8
                n -= 1

        return bytes(buf)

    # noinspection DuplicatedCode
    def decrypt(self, buf: bytes, length: int = None) -> bytes:
        buf = list(buf)
        n = length or len(buf)
        i = 0

        if self.nbuf != 0:
            while self.nbuf != 0 and n != 0:
                buf[i] ^= (self.sbuf >> (32 - self.nbuf)) & 0xFF
                self.mbuf ^= (buf[i] & 0xFF) << (32 - self.nbuf)
                i += 1
                self.nbuf -= 8
                n -= 1

            if self.nbuf != 0:
                return bytes(buf)

            self._mac(self.mbuf)

        j = n & ~0x03

        while i < j:
            self._cycle()
            t = shift4(buf, i)
            t ^= self.sbuf
            self._mac(t)
            pack4(buf, i, t)
            i += 4

        n &= 0x03

        if n != 0:
            self._cycle()
            self.mbuf = 0
            self.nbuf = 32

            while self.nbuf != 0 and n != 0:
                buf[i] ^= (self.sbuf >> (32 - self.nbuf)) & 0xFF
                self.mbuf ^= (buf[i] & 0xFF) << (32 - self.nbuf)
                i += 1
                self.nbuf -= 8
                n -= 1

        return bytes(buf)

    def finish(self, length: int = 16) -> bytes:
        buf = [0x00] * length
        n = length
        i = 0

        if self.nbuf != 0:
            self._mac(self.mbuf)

        self._cycle()
        self._add_key(INITKONST ^ (self.nbuf << 3))

        self.nbuf = 0

        for j in range(0, N):
            self.R[j] ^= self.CRC[j]

        self._diffuse()

        while n > 0:
            self._cycle()

            if n >= 4:
                pack4(buf, i, self.sbuf)
                n -= 4
                i += 4
            else:
                for j in range(0, n):
                    buf[i + j] = (self.sbuf >> (i * 8)) & 0xFF
                break

        return bytes(buf)

    def __init__(self, key: bytes) -> None:
        self.set_key(key)
