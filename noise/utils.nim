# Utility procedures for key generation, DH, hashing, and AEAD operations.

import std/[sysrand]
import monocypher
import nimcrypto/[sha2]
import bearssl/blockx
import stew/[ptrops]
import bearssl/abi/inner
import ./constants
import ./types

# Convert string to byte sequence
proc strToBytes*(s: string): seq[byte] =
  result = @[]
  for c in s: result.add(byte(c))

# Generate a new keypair using random bytes
proc generateKeypair*(): KeyPair =
  let randBytes = urandom(DHLEN)
  copyMem(addr result.private[0], unsafeAddr randBytes[0], DHLEN)
  result.`public` = crypto_key_exchange_public_key(result.private)

# Perform Diffie-Hellman key exchange
proc dh*(priv: array[DHLEN, byte], pub: array[DHLEN, byte]): array[DHLEN, byte] =
  result = crypto_key_exchange(priv, pub)

# Compute SHA256 hash of data
proc hash*(data: openArray[byte]): array[HASHLEN, byte] =
  var ctx: sha256
  ctx.init()
  ctx.update(data)
  result = ctx.finish().data

# Put a uint64 into a byte array in little-endian order
proc putLe64*(buf: var openArray[byte], offset: int, value: uint64) =
  var v = value
  for i in 0..<8:
    buf[offset + i] = byte(v and 0xFF)
    v = v shr 8

# AEAD encryption using ChaChaPoly
proc aeadEncrypt*(key: array[KEYLEN, byte], nonce: array[12, byte], ad, plaintext: openArray[byte]): seq[byte] =
  result = newSeq[byte](plaintext.len + 16)
  if plaintext.len > 0:
    copyMem(addr result[0], unsafeAddr plaintext[0], plaintext.len)

  var tag: array[16, byte]
  let adPtr = if ad.len > 0: unsafeAddr ad[0] else: nil
  poly1305CtmulRun(
    unsafeAddr key[0],
    unsafeAddr nonce[0],
    baseAddr(result),
    uint(plaintext.len),
    adPtr,
    uint(ad.len),
    baseAddr(tag),
    cast[Chacha20Run](chacha20CtRun),
    1.cint
  )
  copyMem(addr result[plaintext.len], addr tag[0], 16)

# AEAD decryption using ChaChaPoly
proc aeadDecrypt*(key: array[KEYLEN, byte], nonce: array[12, byte], ad, ciphertext: openArray[byte]): seq[byte] =
  if ciphertext.len < 16:
    raise newException(ValueError, "invalid ciphertext")
  let ctLen = ciphertext.len - 16
  result = newSeq[byte](ctLen)
  if ctLen > 0:
    copyMem(addr result[0], unsafeAddr ciphertext[0], ctLen)
  var tag: array[16, byte]
  copyMem(addr tag[0], unsafeAddr ciphertext[ctLen], 16)
  let adPtr = if ad.len > 0: unsafeAddr ad[0] else: nil
  poly1305CtmulRun(
    unsafeAddr key[0],
    unsafeAddr nonce[0],
    baseAddr(result),
    uint(ctLen),
    adPtr,
    uint(ad.len),
    baseAddr(tag),
    cast[Chacha20Run](chacha20CtRun),
    0.cint
  )