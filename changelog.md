## 0.11.102.0

 - Add Eq instance for Ctx
 - add start and startlazy producing Ctx

## 0.11.101.0

 - Add `hkdf` function providing HKDF-SHA256 conforming to RFC5869
 - Declare `Crypto.Hash.SHA256` module `-XTrustworthy`
 - Remove ineffective RULES
 - Convert to `CApiFFI`
 - Added `...AndLength` variants of hashing functions:

      - `finalizeAndLength`
      - `hashlazyAndLength`
      - `hmaclazyAndLength`

 - Minor optimizations in `hmac` and `hash`

## 0.11.100.1

 - Use `__builtin_bswap{32,64}` only with GCC >= 4.3
   ([#1](https://github.com/hvr/cryptohash-sha256/issues/1))

## 0.11.100.0

 - new `hmac` and `hmaclazy` functions providing HMAC-SHA256
   computation conforming to RFC2104 and RFC4231
 - fix unaligned memory-accesses

## 0.11.7.2

 - switch to 'safe' FFI for calls where overhead becomes neglible
 - removed inline assembly in favour of portable C constructs
 - fix 32bit length overflow bug in `hash` function
 - fix inaccurate context-size
 - add context-size verification to incremental API operations

## 0.11.7.1

 - first version forked off `cryptohash-0.11.7` release
