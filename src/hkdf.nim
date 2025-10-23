# HKDF (HMAC-based Key Derivation Function) implementation using SHA256.

import bearssl/[kdf, hash]
import nimcrypto/[sha2]
import ./constants
import ./types

# Generic HKDF procedure
proc hkdf*[T: sha256, len: static int](
    _: type[T],
    salt, ikm, info: openArray[byte],
    outputs: var openArray[HkdfResult[len]],
) =
  var ctx: HkdfContext
  hkdfInit(
    ctx,
    addr sha256Vtable,
    if salt.len > 0:
      unsafeAddr salt[0]
    else:
      nil,
    csize_t(salt.len),
  )
  hkdfInject(
    ctx,
    if ikm.len > 0:
      unsafeAddr ikm[0]
    else:
      nil,
    csize_t(ikm.len),
  )
  hkdfFlip(ctx)
  for i in 0 .. outputs.high:
    discard hkdfProduce(
      ctx,
      if info.len > 0:
        unsafeAddr info[0]
      else:
        nil,
      csize_t(info.len),
      addr outputs[i][0],
      csize_t(outputs[i].len),
    )

# Convenience HKDF for producing seq of HASHLEN arrays
proc hkdf*(salt, ikm: openArray[byte], numOutputs: int): seq[array[HASHLEN, byte]] =
  var outputs = newSeq[array[HASHLEN, byte]](numOutputs)
  hkdf[sha256, HASHLEN](sha256, salt, ikm, @[], outputs)
  result = outputs