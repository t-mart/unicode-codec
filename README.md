# unicodec

A Unicode encoding and decoding implementation, written in Python. Specifically avoids using
the standard library `str.encode` or `bytes.decode` functions, but other things are fair game.

```python
>>> import unicodec
>>> my_way = codec.encode('abc', 'utf-16be')
>>> stdlib_way = "abc".encode('utf-16be')
>>> my_way == stdlib_way
True
```

## Encoding Schemes Supported

The following schemes are supported:

- `utf-8`
- `utf-8-sig`
- `utf-16be`
- `utf-16le`
- `utf-16`
- `utf-32be`
- `utf-32le`
- `utf-32`

When encoding, the `utf-8-sig`, `utf-16`, and `utf-32` schemes prefix their outputs with byte order
marks. For `utf-16` and `utf-32`, little-endian is chosen automatically.

When decoding, the `utf-8-sig`, `utf-16`, and `utf-32` schemes these remove an initial byte order
mark from the sequence if one exists (and the decoding respects the endianness of that BOM). If no
byte order mark exists, little-endian is assumed.

The above affinity for little-endian above is a result of the lack of a prescription by the Unicode
standard in this circumstance. See <https://stackoverflow.com/a/36550597/235992>.

## Conformance

Additionally, care is taken to ensure
[conformance](https://www.unicode.org/versions/Unicode14.0.0/ch03.pdf) to
the rules of the standard. Therefore, the following throw an exception:

- Decoding a sequence that is missing necessary additional units (`utf-8`, `utf-16`).
- Encoding a surrogate value (`0xD800` - `0xDFFF`).
- Decoding a sequence that would generate a surrogate value or a value greater than the standard
  has allocated (`0x10FFFF`).
- Decoding a `utf-8` sequence that uses more code units than necessary to encode that
  codepoint.
- Decoding a `utf-8` sequence with ill-formed leading or continuation bytes.
- Decoding a `utf-16` sequence with ill-formed high or low surrogate.

Has a decent battery of tests that check all of the above.

This was just a fun project to learn more about the Unicode schemes.
