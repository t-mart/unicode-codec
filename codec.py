from collections.abc import Iterator
from typing import Literal

# TODO add support for non-endian codecs (utf-16, utf-32), which use the presence of the BOM to
# determine endianness (or, if it does not exist, assume big endian? double check this)
# yes, this is correct: "the byte order is determined by a byte order mark, if present at the
# beginning of the data stream, otherwise it is big-endian."
# - https://unicode.org/faq/utf_bom.html#gen6
# TODO error if BOMs are present where not allowed:
# https://www.unicode.org/versions/Unicode14.0.0/ch02.pdf#G13708
# TODO See https://www.unicode.org/versions/Unicode14.0.0/ch03.pdf for ill formed possibilies, which
# we should error on.

ByteOrderT = Literal["big", "little"]


def _get_unit(
    iterator: Iterator[int], unit_byte_count: int, byteorder: ByteOrderT = "big"
) -> int:
    try:
        the_bytes = [next(iterator) for _ in range(unit_byte_count)]
    except StopIteration as stop_iteration:
        raise ValueError("Incomplete encoding: expected more bytes") from stop_iteration

    return int.from_bytes(the_bytes, byteorder=byteorder)


def utf8_encode(s: str) -> bytes:
    buffer = []
    for c in s:
        codepoint = ord(c)
        if codepoint <= 0x80:
            buffer.append(codepoint)
        elif codepoint <= 0x800:
            b1 = 0b1100_0000 + (codepoint >> 6)
            b2 = 0b1000_0000 + (codepoint & 0b0011_1111)
            buffer.extend([b1, b2])
        elif codepoint <= 0x10000:
            b1 = 0b1110_0000 + (codepoint >> 12)
            b2 = 0b1000_0000 + ((codepoint >> 6) & 0b0011_1111)
            b3 = 0b1000_0000 + (codepoint & 0b0011_1111)
            buffer.extend([b1, b2, b3])
        elif codepoint <= 0x10FFFF:
            b1 = 0b1111_0000 + (codepoint >> 18)
            b2 = 0b1000_0000 + ((codepoint >> 12) & 0b0011_1111)
            b3 = 0b1000_0000 + ((codepoint >> 6) & 0b0011_1111)
            b4 = 0b1000_0000 + (codepoint & 0b0011_1111)
            buffer.extend([b1, b2, b3, b4])
    return bytes(buffer)


def utf8_decode(buf: bytes) -> str:
    codepoints = []
    buf_it = iter(buf)

    while True:
        try:
            byte1 = _get_unit(buf_it, 1)
        except ValueError:
            break  # if we're here, we're finished processing the buffer

        if byte1 >> 7 == 0:
            codepoints.append(byte1)
            continue

        byte2 = _get_unit(buf_it, 1)
        if byte1 >> 5 == 0b0000_0110:
            codepoint = ((byte1 & 0b0001_1111) << 6) + (byte2 & 0b0011_1111)
            codepoints.append(codepoint)
            continue

        byte3 = _get_unit(buf_it, 1)
        if byte1 >> 4 == 0b0000_1110:
            codepoint = (
                ((byte1 & 0b0000_1111) << 12)
                + ((byte2 & 0b0011_1111) << 6)
                + (byte3 & 0b0011_1111)
            )
            codepoints.append(codepoint)
            continue

        byte4 = _get_unit(buf_it, 1)
        if byte1 >> 3 == 0b0001_1110:
            codepoint = (
                ((byte1 & 0b0000_0111) << 18)
                + ((byte2 & 0b0011_1111) << 12)
                + ((byte3 & 0b0011_1111) << 6)
                + (byte4 & 0b0011_1111)
            )
            codepoints.append(codepoint)
            continue

        raise ValueError("Invalid encoding")

    return "".join(chr(codepoint) for codepoint in codepoints)


def utf16_encode(s: str, byteorder: ByteOrderT = "big") -> bytes:
    buffer = []
    for c in s:
        codepoint = ord(c)
        if codepoint < 0x10000:
            # c won't be in D800 - DFFF, bc that's the surrogate range (see below)
            buffer.append(codepoint.to_bytes(2, byteorder))
        else:
            shifted = codepoint - 0x10000
            unit1 = 0xD800 + (shifted >> 10)
            unit2 = 0xDC00 + (shifted & 0b0011_1111_1111)
            buffer.extend(unit.to_bytes(2, byteorder) for unit in [unit1, unit2])

    return b"".join(buffer)


def utf16_decode(buf: bytes, byteorder: ByteOrderT = "big") -> str:
    codepoints = []
    buf_it = iter(buf)

    while True:
        try:
            unit1 = _get_unit(buf_it, 2, byteorder=byteorder)
        except ValueError:
            break  # if we're here, we're finished processing the buffer

        if unit1 >> 10 == 0b110110:
            unit2 = _get_unit(buf_it, 2, byteorder=byteorder)
            codepoint = (
                0x10000 + ((unit1 & 0b11_1111_1111) << 10) + (unit2 & 0b11_1111_1111)
            )
            codepoints.append(codepoint)
        else:
            codepoints.append(unit1)

    return "".join(chr(c) for c in codepoints)


def utf32_encode(s: str, byteorder: ByteOrderT = "big") -> bytes:
    buffer = []
    for c in s:
        codepoint = ord(c)
        buffer.append(codepoint.to_bytes(4, byteorder))

    return b"".join(buffer)


def utf32_decode(buf: bytes, byteorder: ByteOrderT = "big") -> str:
    codepoints = []
    buf_it = iter(buf)

    while True:
        try:
            codepoint = _get_unit(buf_it, 4, byteorder=byteorder)
        except ValueError:
            break  # if we're here, we're finished processing the buffer

        codepoints.append(codepoint)

    return "".join(chr(c) for c in codepoints)


def encode(s: str, encoding: str) -> bytes:
    if encoding == "utf-8":
        return utf8_encode(s)
    elif encoding == "utf-16be":
        return utf16_encode(s, "big")
    elif encoding == "utf-16le":
        return utf16_encode(s, "little")
    # elif encoding == "utf-16":
    elif encoding == "utf-32be":
        return utf32_encode(s, "big")
    elif encoding == "utf-32le":
        return utf32_encode(s, "little")
    # elif encoding == "utf-32":
    raise ValueError(f"unknown encoding {encoding}")


def decode(buf: bytes, encoding: str) -> str:
    if encoding == "utf-8":
        return utf8_decode(buf)
    elif encoding == "utf-16be":
        return utf16_decode(buf, "big")
    elif encoding == "utf-16le":
        return utf16_decode(buf, "little")
    # elif encoding == "utf-16":
    elif encoding == "utf-32be":
        return utf32_decode(buf, "big")
    elif encoding == "utf-32le":
        return utf32_decode(buf, "little")
    # elif encoding == "utf-32":
    raise ValueError(f"unknown encoding {encoding}")
