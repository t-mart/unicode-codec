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

The following schemes are supported:

- `utf-8`
- `utf-8-sig` (On decode, consume BOM if it exists, otherwise, just do `utf-8`. On encode,
  prefix with BOM and do normal encode.)
- `utf-16be`
- `utf-16le`
- `utf-16` (On decode, if BOM exists, choose endianness from it, or else assume little-endian.
  On encode, prefix with little-endian BOM and do little-endian encode.)
- `utf-32be`
- `utf-32le`
- `utf-32` (On decode, if BOM exists, choose endianness from it, or else assume little-endian.
  On encode, prefix with little-endian BOM and do little-endian encode.)

(Note that when we have to make an assumption for a non-endian-specified scheme (`utf-16`,
`utf-32`) or choose a decoding endianness for such a scheme, we choose **little**. This is what
Python appears to do by default. The Unicode standard does not seem to have a strong
prescription about this. See <https://stackoverflow.com/a/36550597/235992>.)

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
