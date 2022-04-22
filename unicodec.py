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

_DEFAULT_BYTE_ORDER: _ByteOrderT = "little"


class UnicodeException(Exception):
    """Base class for exceptions"""


class DecodeException(UnicodeException):
    """Indicates an issue in decoding"""


class EncodeException(UnicodeException):
    """Indicates an issue in encoding"""


class UnsupportedEncodingException(UnicodeException):
    """Indicates unsupported (or unknown) encoding has been specified"""


def _get_unit(
    iterator: Iterator[int], unit_byte_count: int, byteorder: _ByteOrderT = "big"
) -> int:
    try:
        the_bytes = [next(iterator) for _ in range(unit_byte_count)]
    except StopIteration as stop_iteration:
        raise DecodeException(
            "Invalid encoding, expected more bytes"
        ) from stop_iteration

    return int.from_bytes(the_bytes, byteorder=byteorder)


def _ord_only_scalars(char: str) -> int:
    scalar = ord(char)
    if 0xD800 <= scalar <= 0xDFFF:
        raise EncodeException("Surrogates not allowed")
    return scalar


def _check_valid_continuation(*units: int) -> None:
    for unit in units:
        if unit < 0b1000_0000 or unit > 0b1011_1111:
            raise DecodeException("Invalid continuation byte")


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
        except DecodeException:
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
                raise DecodeException(
                    f"Unnecessary 3 code unit sequence: {(unit1, unit2, unit3)}"
                )
            if unit1 == 0xED and unit2 > 0x9F:
                raise DecodeException(
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
                raise DecodeException(
                    f"Unnecessary 4 code unit sequence: {(unit1, unit2, unit3, unit4)}"
                )
            if unit1 == 0xF4 and unit2 > 0x8F:
                raise DecodeException(
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
            raise DecodeException("Ill-formed leading code unit of utf-8 sequence")

    return "".join(chr(codepoint) for codepoint in codepoints)


def _utf8_sig_decode(buf: bytes) -> str:
    """Remove the BOM if its there. Otherwise, decode as normal."""
    return _utf8_decode(buf.removeprefix(_UTF_8_BOM))


def _utf16_e_encode(string: str, byteorder: _ByteOrderT) -> bytes:
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
    return _UTF_16_LE_BOM + _utf16_e_encode(string, _DEFAULT_BYTE_ORDER)


def _utf16_e_decode(buf: bytes, byteorder: _ByteOrderT) -> str:
    codepoints = []
    buf_it = iter(buf)

    while True:
        try:
            unit1 = _get_unit(buf_it, 2, byteorder=byteorder)
        except DecodeException:
            break  # if we're here, we're finished processing the buffer

        if 0xD800 <= unit1 <= 0xDC00:
            unit2 = _get_unit(buf_it, 2, byteorder=byteorder)
            if unit2 < 0xDC00 or unit2 > 0xDFFF:
                raise DecodeException("Invalid low surrogate")
            codepoint = (
                0x10000 + ((unit1 & 0b11_1111_1111) << 10) + (unit2 & 0b11_1111_1111)
            )

            codepoints.append(codepoint)
        elif 0xDC00 <= unit1 <= 0xDFFF:
            raise DecodeException("Invalid high surrogate")
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
    if buf.startswith(_UTF_16_LE_BOM):
        return _utf16_e_decode(buf.removeprefix(_UTF_16_LE_BOM), "little")
    if buf.startswith(_UTF_16_BE_BOM):
        return _utf16_e_decode(buf.removeprefix(_UTF_16_BE_BOM), "big")
    return _utf16_e_decode(buf, _DEFAULT_BYTE_ORDER)


def _utf32_e_encode(string: str, byteorder: _ByteOrderT) -> bytes:
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
    return _UTF_32_LE_BOM + _utf32_e_encode(string, _DEFAULT_BYTE_ORDER)


def _utf32_e_decode(buf: bytes, byteorder: _ByteOrderT) -> str:
    codepoints = []
    buf_it = iter(buf)

    while True:
        try:
            codepoint = _get_unit(buf_it, 4, byteorder=byteorder)
        except DecodeException:
            break  # if we're here, we're finished processing the buffer

        # ill-formed cases
        if 0xD800 <= codepoint <= 0xDFFF:
            raise DecodeException(f"Can't decode surrogate {hex(codepoint)}")
        if 0x10FFFF < codepoint:
            raise DecodeException(f"Codepoint too large: {hex(codepoint)}")

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
    if buf.startswith(_UTF_32_LE_BOM):
        return _utf32_e_decode(buf.removeprefix(_UTF_32_LE_BOM), "little")
    if buf.startswith(_UTF_32_BE_BOM):
        return _utf32_e_decode(buf.removeprefix(_UTF_32_BE_BOM), "big")
    return _utf32_e_decode(buf, _DEFAULT_BYTE_ORDER)


def encode(string: str, encoding: str) -> bytes:
    """
    Encode a string with a Unicode encoding into bytes. A UnicodeEncodeException is
    thrown if the encoding cannot be performed for some reason or if the encoding is not
    supported.

    The supported encodings are: utf-8, utf-8-sig, utf-16be, utf-16le, utf-16, utf-32be,
    utf-32le, utf-32.
    """
    match encoding:
        case "utf-8":
            enc = _utf8_encode(string)
        case "utf-8-sig":
            enc = _utf8_sig_encode(string)
        case "utf-16be":
            enc = _utf16_e_encode(string, "big")
        case "utf-16le":
            enc = _utf16_e_encode(string, "little")
        case "utf-16":
            enc = _utf16_ne_encode(string)
        case "utf-32be":
            enc = _utf32_e_encode(string, "big")
        case "utf-32le":
            enc = _utf32_e_encode(string, "little")
        case "utf-32":
            enc = _utf32_ne_encode(string)
        case _:
            raise UnsupportedEncodingException(f"Unknown encoding {encoding}")
    return enc


def decode(buf: bytes, encoding: str) -> str:
    """
    Decode a bytes sequence in a Unicode encoding into a string. A
    UnicodeDecodeException is thrown if the decoding cannot be performed for some reason
    or if the encoding is not supported.

    The supported encodings are: utf-8, utf-8-sig, utf-16be, utf-16le, utf-16, utf-32be,
    utf-32le, utf-32.
    """
    match encoding:
        case "utf-8":
            dec = _utf8_decode(buf)
        case "utf-8-sig":
            dec = _utf8_sig_decode(buf)
        case "utf-16be":
            dec = _utf16_e_decode(buf, "big")
        case "utf-16le":
            dec = _utf16_e_decode(buf, "little")
        case "utf-16":
            dec = _utf16_ne_decode(buf)
        case "utf-32be":
            dec = _utf32_e_decode(buf, "big")
        case "utf-32le":
            dec = _utf32_e_decode(buf, "little")
        case "utf-32":
            dec = _utf32_ne_decode(buf)
        case _:
            raise UnsupportedEncodingException(f"Unknown encoding {encoding}")
    return dec
