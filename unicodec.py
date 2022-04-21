"""
A Unicode encoding and decoding implementation.

Specifically avoids using the standard library str.encode or bytes.decode functions, but
other things are fair game.
"""
from collections.abc import Iterator
from typing import Literal

_ByteOrderT = Literal["big", "little"]

_UTF_8_CONT_MASK = (1 << 6) - 1  # 0b0011_111
_UTF_8_CONT_LEAD = 1 << 7  # 0b1000_0000

_UTF_8_BOM = b"\xef\xbb\xbf"
_UTF_16_LE_BOM = b"\xff\xfe"
_UTF_16_BE_BOM = b"\xfe\xff"
_UTF_32_LE_BOM = b"\xff\xfe\x00\x00"
_UTF_32_BE_BOM = b"\x00\x00\xfe\xff"


class UnicodeException(Exception):
    """Base class for exceptions"""


class UnicodeDecodeException(UnicodeException):
    """Indicates an issue in decoding"""


class UnicodeEncodeException(UnicodeException):
    """Indicates an issue in encoding"""


def _get_unit(
    iterator: Iterator[int], unit_byte_count: int, byteorder: _ByteOrderT = "big"
) -> int:
    try:
        the_bytes = [next(iterator) for _ in range(unit_byte_count)]
    except StopIteration as stop_iteration:
        raise UnicodeDecodeException(
            "Invalid encoding, expected more bytes"
        ) from stop_iteration

    return int.from_bytes(the_bytes, byteorder=byteorder)


def _ord_only_scalars(char: str) -> int:
    scalar = ord(char)
    if 0xD800 <= scalar <= 0xDFFF:
        raise UnicodeEncodeException("Surrogates not allowed")
    return scalar


def _check_valid_continuation(*units: int) -> None:
    for unit in units:
        if unit < 0b1000_0000 or unit > 0b1011_1111:
            raise UnicodeDecodeException("Invalid continuation byte")


def _utf8_encode(string: str) -> bytes:
    buffer = []
    for char in string:
        codepoint = _ord_only_scalars(char)
        if codepoint <= 0x80:
            buffer.append(codepoint)
        elif codepoint <= 0x800:
            unit1 = 0b1100_0000 | (codepoint >> 6)
            unit2 = _UTF_8_CONT_LEAD | (codepoint & _UTF_8_CONT_MASK)
            buffer.extend([unit1, unit2])
        elif codepoint <= 0x10000:
            unit1 = 0b1110_0000 | (codepoint >> 12)
            unit2 = _UTF_8_CONT_LEAD | ((codepoint >> 6) & _UTF_8_CONT_MASK)
            unit3 = _UTF_8_CONT_LEAD | (codepoint & _UTF_8_CONT_MASK)
            buffer.extend([unit1, unit2, unit3])
        else:
            unit1 = 0b1111_0000 | (codepoint >> 18)
            unit2 = _UTF_8_CONT_LEAD | ((codepoint >> 12) & _UTF_8_CONT_MASK)
            unit3 = _UTF_8_CONT_LEAD | ((codepoint >> 6) & _UTF_8_CONT_MASK)
            unit4 = _UTF_8_CONT_LEAD | (codepoint & _UTF_8_CONT_MASK)
            buffer.extend([unit1, unit2, unit3, unit4])
    return bytes(buffer)


def _utf8_sig_encode(string: str) -> bytes:
    return _UTF_8_BOM + _utf8_encode(string)


def _utf8_decode(buf: bytes) -> str:
    codepoints = []
    buf_it = iter(buf)

    while True:
        try:
            unit1 = _get_unit(buf_it, 1)
        except UnicodeDecodeException:
            break  # if we're here, we've decoded a number of complete codepoints

        if unit1 & 0b1000_0000 == 0:
            codepoints.append(unit1)
        elif 0b1100_0010 <= unit1 <= 0b1101_1111:
            # The lower bound of this condition would seem to be 0b1100_0000 according
            # to the 0b110x_xxxx format found in reference material. But in truth, the
            # lower bound is 0b1100_0010 because for anything lower only generates
            # codepoints of at most 7 bits, so they should be single unit sequences.
            unit2 = _get_unit(buf_it, 1)
            _check_valid_continuation(unit2)

            codepoint = ((unit1 & 0b0001_1111) << 6) | (unit2 & _UTF_8_CONT_MASK)
            codepoints.append(codepoint)
        elif 0xE0 <= unit1 <= 0xEF:
            unit2, unit3 = [_get_unit(buf_it, 1) for _ in range(2)]
            _check_valid_continuation(unit2, unit3)

            # ill-formed cases
            if unit1 == 0xE0 and unit2 < 0xA0:
                raise UnicodeDecodeException(
                    f"Unnecessary 3 code unit sequence: {(unit1, unit2, unit3)}"
                )
            if unit1 == 0xED and unit2 > 0x9F:
                raise UnicodeDecodeException(
                    f"Code units decode to surrogate: {(unit1, unit2, unit3)}"
                )

            codepoint = (
                ((unit1 & 0b0000_1111) << 12)
                | ((unit2 & _UTF_8_CONT_MASK) << 6)
                | (unit3 & _UTF_8_CONT_MASK)
            )
            codepoints.append(codepoint)
            continue
        elif 0b1111_0000 <= unit1 <= 0b1111_0100:
            unit2, unit3, unit4 = [_get_unit(buf_it, 1) for _ in range(3)]
            _check_valid_continuation(unit2, unit3, unit4)

            # ill-formed cases
            if unit1 == 0xF0 and unit2 < 0x90:
                raise UnicodeDecodeException(
                    f"Unnecessary 4 code unit sequence: {(unit1, unit2, unit3, unit4)}"
                )
            if unit1 == 0xF4 and unit2 > 0x8F:
                raise UnicodeDecodeException(
                    f"Codepoint out of Unicode range: {(unit1, unit2, unit3, unit4)}"
                )

            codepoint = (
                ((unit1 & 0b0000_0111) << 18)
                | ((unit2 & _UTF_8_CONT_MASK) << 12)
                | ((unit3 & _UTF_8_CONT_MASK) << 6)
                | (unit4 & _UTF_8_CONT_MASK)
            )
            codepoints.append(codepoint)
            continue
        else:
            raise UnicodeDecodeException(
                "Ill-formed leading code unit of utf-8 sequence"
            )

    return "".join(chr(codepoint) for codepoint in codepoints)


def _utf8_sig_decode(buf: bytes) -> str:
    """Remove the BOM if its there. Otherwise, decode as normal."""
    if buf[:3] == _UTF_8_BOM:
        return _utf8_decode(buf[3:])
    return _utf8_decode(buf)


def _utf16_e_encode(string: str, byteorder: _ByteOrderT = "big") -> bytes:
    buffer = []
    for char in string:
        codepoint = _ord_only_scalars(char)
        if codepoint < 0x10000:
            buffer.append(codepoint.to_bytes(2, byteorder))
        else:
            shifted = codepoint - 0x10000
            unit1 = 0xD800 + (shifted >> 10)
            unit2 = 0xDC00 + (shifted & 0b0011_1111_1111)
            buffer.extend(unit.to_bytes(2, byteorder) for unit in [unit1, unit2])

    return b"".join(buffer)


def _utf16_ne_encode(string: str) -> bytes:
    """
    Encode "utf-16" (no endian specified). (We follow Python, which chooses little
    endian here with an appropriate BOM.)
    """
    return _UTF_16_LE_BOM + _utf16_e_encode(string, "little")


def _utf16_e_decode(buf: bytes, byteorder: _ByteOrderT = "big") -> str:
    codepoints = []
    buf_it = iter(buf)

    while True:
        try:
            unit1 = _get_unit(buf_it, 2, byteorder=byteorder)
        except UnicodeDecodeException:
            break  # if we're here, we're finished processing the buffer

        if 0xD800 <= unit1 <= 0xDC00:
            unit2 = _get_unit(buf_it, 2, byteorder=byteorder)
            if unit2 < 0xDC00 or unit2 > 0xDFFF:
                raise UnicodeDecodeException("Invalid low surrogate")
            codepoint = (
                0x10000 + ((unit1 & 0b11_1111_1111) << 10) + (unit2 & 0b11_1111_1111)
            )

            codepoints.append(codepoint)
        elif 0xDC00 <= unit1 <= 0xDFFF:
            raise UnicodeDecodeException("Invalid high surrogate")
        else:
            codepoints.append(unit1)

    return "".join(chr(c) for c in codepoints)


def _utf16_ne_decode(buf: bytes) -> str:
    """
    Decode "utf-16" (no endian specified). If a BOM prefixes the text, respect it and
    remove it from the resulting string. Otherwise, assume little endian.

    (There's not really a prescription about which endian to use when it's not provided
    in this case. See: https://stackoverflow.com/a/36550597/235992. I'm just following
    the Python stdlib.)
    """
    if buf[:2] == _UTF_16_LE_BOM:
        return _utf16_e_decode(buf[2:], "little")
    if buf[:2] == _UTF_16_BE_BOM:
        return _utf16_e_decode(buf[2:], "big")
    return _utf16_e_decode(buf, "little")


def _utf32_e_encode(string: str, byteorder: _ByteOrderT = "big") -> bytes:
    buffer = []
    for char in string:
        codepoint = _ord_only_scalars(char)
        buffer.append(codepoint.to_bytes(4, byteorder))

    return b"".join(buffer)


def _utf32_ne_encode(string: str) -> bytes:
    """
    Encode "utf-32" (no endian specified). (We follow Python, which chooses little
    endian here with an appropriate BOM.)
    """
    return _UTF_32_LE_BOM + _utf32_e_encode(string, "little")


def _utf32_e_decode(buf: bytes, byteorder: _ByteOrderT = "big") -> str:
    codepoints = []
    buf_it = iter(buf)

    while True:
        try:
            codepoint = _get_unit(buf_it, 4, byteorder=byteorder)
        except UnicodeDecodeException:
            break  # if we're here, we're finished processing the buffer

        # ill-formed cases
        if 0xD800 <= codepoint <= 0xDFFF:
            raise UnicodeDecodeException(f"Can't decode surrogate {hex(codepoint)}")
        if 0x10FFFF < codepoint:
            raise UnicodeDecodeException(f"Codepoint too large: {hex(codepoint)}")

        codepoints.append(codepoint)

    return "".join(chr(c) for c in codepoints)


def _utf32_ne_decode(buf: bytes) -> str:
    """
    Decode "utf-32" (no endian specified). If a BOM prefixes the text, respect it and
    remove it from the resulting string. Otherwise, assume little endian.

    (There's not really a prescription about which endian to use when it's not provided
    in this case. See: https://stackoverflow.com/a/36550597/235992. I'm just following
    the Python stdlib.)
    """
    if buf[:4] == _UTF_32_LE_BOM:
        return _utf32_e_decode(buf[4:], "little")
    if buf[:4] == _UTF_32_BE_BOM:
        return _utf32_e_decode(buf[4:], "big")
    return _utf32_e_decode(buf, "little")


def encode(s: str, encoding: str) -> bytes:
    if encoding == "utf-8":
        return _utf8_encode(s)
    if encoding == "utf-8-sig":
        return _utf8_sig_encode(s)
    elif encoding == "utf-16be":
        return _utf16_e_encode(s, "big")
    elif encoding == "utf-16le":
        return _utf16_e_encode(s, "little")
    elif encoding == "utf-16":
        return _utf16_ne_encode(s)
    elif encoding == "utf-32be":
        return _utf32_e_encode(s, "big")
    elif encoding == "utf-32le":
        return _utf32_e_encode(s, "little")
    elif encoding == "utf-32":
        return _utf32_ne_encode(s)
    raise UnicodeEncodeException(f"unknown encoding {encoding}")


def decode(buf: bytes, encoding: str) -> str:
    if encoding == "utf-8":
        return _utf8_decode(buf)
    if encoding == "utf-8-sig":
        return _utf8_sig_decode(buf)
    elif encoding == "utf-16be":
        return _utf16_e_decode(buf, "big")
    elif encoding == "utf-16le":
        return _utf16_e_decode(buf, "little")
    elif encoding == "utf-16":
        return _utf16_ne_decode(buf)
    elif encoding == "utf-32be":
        return _utf32_e_decode(buf, "big")
    elif encoding == "utf-32le":
        return _utf32_e_decode(buf, "little")
    elif encoding == "utf-32":
        return _utf32_ne_decode(buf)
    raise UnicodeDecodeException(f"unknown encoding {encoding}")