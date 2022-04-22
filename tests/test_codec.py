"""Tests for unicodec"""
import pytest

from unicodec import UnicodeDecodeException, UnicodeEncodeException, decode, encode

ENCODINGS = [
    "utf-8",
    "utf-8-sig",
    "utf-16",
    "utf-16be",
    "utf-16le",
    "utf-32",
    "utf-32be",
    "utf-32le",
]

TEST_STRINGS = [
    "",
    "r",
    "ć",
    " ऀ",
    "𐐷",
    "𤭢",
    "👩🏼‍❤️‍💋‍👩🏿",
]

UTF_8_BOM = b"\xef\xbb\xbf"
UTF_16_LE_BOM = b"\xff\xfe"
UTF_16_BE_BOM = b"\xfe\xff"
UTF_32_LE_BOM = b"\xff\xfe\x00\x00"
UTF_32_BE_BOM = b"\x00\x00\xfe\xff"


def test_decode_unknown_encoding() -> None:
    """Test that decoding with an unknown scheme throws an exception."""
    with pytest.raises(UnicodeDecodeException):
        decode(b"\x12", "utf-9000")


def test_encode_unknown_encoding() -> None:
    """Test that encoding with an unknown scheme throws an exception."""
    with pytest.raises(UnicodeEncodeException):
        encode("foo", "utf-9000")


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("test_string", TEST_STRINGS)
def test_encode_matches_stdlib(encoding: str, test_string: str) -> None:
    """Test encoding works by testing against stdlib."""
    actual = encode(test_string, encoding)
    expected = test_string.encode(encoding=encoding)
    assert actual == expected


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("test_string", TEST_STRINGS)
def test_decode_matches_stdlib(encoding: str, test_string: str) -> None:
    """Test decoding works by testing against stdlib."""
    encoded_string = test_string.encode(encoding=encoding)

    actual = decode(encoded_string, encoding)
    expected = encoded_string.decode(encoding=encoding)

    assert actual == expected


@pytest.mark.parametrize("encoding", ENCODINGS)
def test_encode_surrogate_not_allowed(encoding: str) -> None:
    """Ensure surrogate scalars can't be encoded."""
    # kinda hate this escape format allows surrogates to be created. AFAIK, this is the
    # only way to create an invalid codepoint
    surrogates = [
        "\uD800",
        "\uDFFF",
        "\U0000D800",
        "\U0000DFFF",
    ]
    for surrogate in surrogates:
        with pytest.raises(UnicodeEncodeException):
            encode(surrogate, encoding)


@pytest.mark.parametrize(
    "sequence",
    [
        (0xC2, 0x7F),  # 2 units, last cont bad
        (0xE1, 0x80, 0x7F),  # 3 units, last cont bad
        (0xE1, 0x7F, 0x80),  # 3 units, first cont bad
        (0xE1, 0x7F, 0x7F),  # 3 units, both cont bad
        (0xF1, 0x80, 0x80, 0x7F),  # 4 units, last cont bad
        (0xF1, 0x80, 0x7F, 0x7F),  # 4 units, mid cont bad
        (0xF1, 0x7F, 0x80, 0x7F),  # 4 units, first cont bad
        (0xF1, 0x80, 0x7F, 0x7F),  # 4 units, last 2 cont bad
        (0xF1, 0x7F, 0x7F, 0x80),  # 4 units, first 2 cont bad
        (0xF1, 0x7F, 0x7F, 0x7F),  # 4 units, all cont bad
    ],
)
def test_utf8_decode_invalid_cont_bytes(sequence: tuple[int, ...]) -> None:
    """
    Test that an exception is thrown when the continuation bytes in a UTF-8 sequence are
    invalid
    """
    with pytest.raises(UnicodeDecodeException):
        decode(bytes(sequence), "utf-8")


@pytest.mark.parametrize("first_unit", range(0xC0, 0xC2))
def test_utf8_decode_unnecessary_two_unit(first_unit: int) -> None:
    """
    Test that an exception is thrown when attempting to decode a 2 code unit character
    when just 1 unit will do.

    See Table 3-7 of https://www.unicode.org/versions/Unicode14.0.0/ch03.pdf.
    """
    sequence = bytes([first_unit, 0x80])
    with pytest.raises(UnicodeDecodeException):
        decode(sequence, "utf-8")


@pytest.mark.parametrize("second_unit", range(0x80, 0xA0))
def test_utf8_decode_unnecessary_three_unit(second_unit: int) -> None:
    """
    Test that an exception is thrown when attempting to decode a 3 code unit character
    when just 2 units will do.

    See Table 3-7 of https://www.unicode.org/versions/Unicode14.0.0/ch03.pdf.
    """
    sequence = bytes([0xE0, second_unit, 0x80])
    with pytest.raises(UnicodeDecodeException):
        decode(sequence, "utf-8")


@pytest.mark.parametrize("second_unit", range(0x80, 0x90))
def test_utf8_decode_unnecessary_four_unit(second_unit: int) -> None:
    """
    Test that an exception is thrown when attempting to decode a 4 code unit character
    when just 3 units will do.

    See Table 3-7 of https://www.unicode.org/versions/Unicode14.0.0/ch03.pdf.
    """
    sequence = bytes([0xF0, second_unit, 0x80, 0x80])
    with pytest.raises(UnicodeDecodeException):
        decode(sequence, "utf-8")


@pytest.mark.parametrize("second_unit", range(0xA0, 0xC0))
def test_utf8_decode_surrogate(second_unit: int) -> None:
    """Test that an exception is thrown when attempting to decode a surrogate"""
    sequence = bytes([0xED, second_unit, 0x80])
    with pytest.raises(UnicodeDecodeException):
        decode(sequence, "utf-8")


def test_utf8_decode_unit_too_large() -> None:
    """
    Test that an exception is thrown when attempting to decode a 4 code unit that
    generates a codepoint greater than Unicode allows (more than 0x10FFFF)

    See Table 3-7 of https://www.unicode.org/versions/Unicode14.0.0/ch03.pdf.
    """

    sequence = bytes([0xF4, 0x90, 0x80, 0x80])
    with pytest.raises(UnicodeDecodeException):
        decode(sequence, "utf-8")


@pytest.mark.parametrize(
    "sequence",
    [
        b"\xc2",  # expecting 2 units
        b"\xe0",  # expecting 3 units
        b"\xe0\xa0",  # expecting 3 units
        b"\xf0",  # expecting 4 units
        b"\xf0\x90",  # expecting 4 units
        b"\xf0\x90\x80",  # expecting 4 units
    ],
)
def test_utf8_decode_missing_continuation(sequence: bytes) -> None:
    """Tests that missing bytes of utf-8 throw an exception"""
    with pytest.raises(UnicodeDecodeException):
        decode(sequence, "utf-8")


@pytest.mark.parametrize(
    "buf,expected",
    [
        (UTF_8_BOM + b"a", "a"),
        (b"a", "a"),
    ],
)
def test_utf8sig_decode_with_bom(buf: bytes, expected: str) -> None:
    """
    Test that text with a BOM (or not) is properly decoded when using the utf-8-sig
    """
    actual = decode(buf, "utf-8-sig")

    assert actual == expected


def test_utf8sig_encode_with_bom() -> None:
    """
    Test that utf-16 encoding text produces little endian with a BOM.
    """
    actual = encode("a", "utf-8-sig")

    assert actual == UTF_8_BOM + b"a"


def test_utf16_decode_lone_surrogate() -> None:
    """
    Tests that missing bytes of utf-16 (a surrogate without a partner) throw an
    exception.
    """
    for surrogate in range(0xD800, 0xE000):
        with pytest.raises(UnicodeDecodeException):
            decode(surrogate.to_bytes(2, "big"), "utf-16be")
        with pytest.raises(UnicodeDecodeException):
            decode(surrogate.to_bytes(2, "little"), "utf-16le")


@pytest.mark.parametrize(
    "sequence,encoding",
    [
        (b"\xdc\x37\xdc\x37", "utf-16-be"),  # high surrogate bad
        (b"\x37\xdc\x37\xdc", "utf-16-le"),  # high surrogate bad
        (b"\xd8\x37\xd8\x37", "utf-16-be"),  # low surrogate bad
        (b"\x37\xd8\x37\xd8", "utf-16-le"),  # low surrogate bad
        (b"\xdc\x37\xd8\x37", "utf-16-be"),  # both surrogate bad
        (b"\x37\xdc\x37\xd8", "utf-16-le"),  # both surrogate bad
    ],
)
def test_utf16_decode_bad_surrogate(sequence: bytes, encoding: str) -> None:
    """
    Tests that missing bytes of utf-16 (a surrogate without a partner) throw an
    exception.
    """
    with pytest.raises(UnicodeDecodeException):
        decode(sequence, encoding)


@pytest.mark.parametrize(
    "buf,expected",
    [
        (UTF_16_BE_BOM + b"\x00\x61", "a"),
        (UTF_16_LE_BOM + b"\x61\x00", "a"),
        (b"\x61\x00", "a"),
    ],
)
def test_utf16_decode_with_bom(buf: bytes, expected: str) -> None:
    """
    Test that text with a BOM (or not) is properly decoded when using the non-endian
    utf-16.
    """
    actual = decode(buf, "utf-16")

    assert actual == expected


def test_utf16_encode_with_bom() -> None:
    """
    Test that utf-16 encoding text produces little endian with a BOM.
    """
    actual = encode("a", "utf-16")

    assert actual == UTF_16_LE_BOM + b"\x61\x00"


def test_utf32_decode_surrogate() -> None:
    """Ensure decoding a surrogate throws an exception for utf32"""
    for surrogate in range(0xD800, 0xE000):
        with pytest.raises(UnicodeDecodeException):
            decode(surrogate.to_bytes(4, "big"), "utf-32be")
        with pytest.raises(UnicodeDecodeException):
            decode(surrogate.to_bytes(4, "little"), "utf-32le")


def test_utf32_decode_too_large() -> None:
    """Ensure decoding a surrogate throws an exception for utf32"""
    with pytest.raises(UnicodeDecodeException):
        decode((0x11_0000).to_bytes(4, "big"), "utf-32be")
    with pytest.raises(UnicodeDecodeException):
        decode((0x11_0000).to_bytes(4, "little"), "utf-32le")


@pytest.mark.parametrize(
    "buf,expected",
    [
        (UTF_32_BE_BOM + b"\x00\x00\x00\x61", "a"),
        (UTF_32_LE_BOM + b"\x61\x00\x00\x00", "a"),
        (b"\x61\x00\x00\x00", "a"),
    ],
)
def test_utf32_decode_with_bom(buf: bytes, expected: str) -> None:
    """
    Test that text with a BOM (or not) is properly decoded when using the non-endian
    utf-32.
    """
    actual = decode(buf, "utf-32")

    assert actual == expected


def test_utf32_encode_with_bom() -> None:
    """
    Test that utf-16 encoding text produces little endian with a BOM.
    """
    actual = encode("a", "utf-32")

    assert actual == UTF_32_LE_BOM + b"\x61\x00\x00\x00"
