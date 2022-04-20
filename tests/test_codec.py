import pytest

from codec import decode, encode

ENCODINGS = [
    "utf-8",
    # "utf-16",
    "utf-16be",
    "utf-16le",
    # "utf-32",
    "utf-32be",
    "utf-32le",
]

TEST_STRINGS = [
    "r",
    "ć",
    " ऀ",
    "𐐷",
    "𤭢",
    "👩🏼‍❤️‍💋‍👩🏿",
]


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("test_string", TEST_STRINGS)
def test_encode(encoding: str, test_string: str) -> None:
    """Test encoding works"""
    actual = encode(test_string, encoding)
    expected = test_string.encode(encoding=encoding)
    assert actual == expected


@pytest.mark.parametrize("encoding", ENCODINGS)
@pytest.mark.parametrize("test_string", TEST_STRINGS)
def test_decode(encoding: str, test_string: str) -> None:
    """Test decoding works"""
    encoded_string = test_string.encode(encoding=encoding)

    actual = decode(encoded_string, encoding)
    expected = encoded_string.decode(encoding=encoding)

    assert actual == expected
