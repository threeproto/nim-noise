import std/[sysrand, strutils]
import monocypher
import nimcrypto/[hmac, sha2]
import bearssl/blockx
import bearssl/[kdf, hash]
import stew/[ptrops, byteutils]
import bearssl/abi/inner

const
  DHLEN = 32
  HASHLEN = 32
  KEYLEN = 32
  MAXNONCE = uint64.high
  PROTOCOL_NAME = "Noise_NN_25519_ChaChaPoly_SHA256"

type
  KeyPair = object
    private: array[DHLEN, byte]
    `public`: array[DHLEN, byte]

type HkdfResult*[len: static int] = array[len, byte]

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

proc hkdf(salt, ikm: openArray[byte], numOutputs: int): seq[array[HASHLEN, byte]] =
  var outputs = newSeq[array[HASHLEN, byte]](numOutputs)
  hkdf[sha256, HASHLEN](sha256, salt, ikm, @[], outputs)
  result = outputs

proc strToBytes(s: string): seq[byte] =
  result = @[]
  for c in s: result.add(byte(c))

proc generateKeypair(): KeyPair =
  let randBytes = urandom(DHLEN)
  copyMem(addr result.private[0], unsafeAddr randBytes[0], DHLEN)
  result.`public` = crypto_key_exchange_public_key(result.private)

proc dh(priv: array[DHLEN, byte], pub: array[DHLEN, byte]): array[DHLEN, byte] =
  result = crypto_key_exchange(priv, pub)

proc hash(data: openArray[byte]): array[HASHLEN, byte] =
  var ctx: sha256
  ctx.init()
  ctx.update(data)
  result = ctx.finish().data

proc putLe64(buf: var openArray[byte], offset: int, value: uint64) =
  var v = value
  for i in 0..<8:
    buf[offset + i] = byte(v and 0xFF)
    v = v shr 8

proc aeadEncrypt(key: array[KEYLEN, byte], nonce: array[12, byte], ad, plaintext: openArray[byte]): seq[byte] =
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

proc aeadDecrypt(key: array[KEYLEN, byte], nonce: array[12, byte], ad, ciphertext: openArray[byte]): seq[byte] =
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

type
  CipherState = ref object
    k: array[KEYLEN, byte]
    n: uint64

proc newCipherState(): CipherState =
  CipherState(n: 0)

proc initializeKey(cs: CipherState, key: array[KEYLEN, byte]) =
  cs.k = key
  cs.n = 0

proc hasKey(cs: CipherState): bool =
  var zeros: array[KEYLEN, byte]
  cs.k != zeros

proc encrypt(cs: CipherState, ad, plaintext: openArray[byte]): seq[byte] =
  if not cs.hasKey():
    return @plaintext
  if cs.n > MAXNONCE:
    raise newException(ValueError, "nonce overflow")
  var nonce: array[12, byte]
  putLe64(nonce, 4, cs.n)
  result = aeadEncrypt(cs.k, nonce, ad, plaintext)
  cs.n.inc

proc decrypt(cs: CipherState, ad, ciphertext: openArray[byte]): seq[byte] =
  if not cs.hasKey():
    return @ciphertext
  if cs.n > MAXNONCE:
    raise newException(ValueError, "nonce overflow")
  var nonce: array[12, byte]
  putLe64(nonce, 4, cs.n)
  result = aeadDecrypt(cs.k, nonce, ad, ciphertext)
  cs.n.inc

type
  SymmetricState = ref object
    cs: CipherState
    ck: array[HASHLEN, byte]
    h: array[HASHLEN, byte]

proc initializeSymmetric(ss: SymmetricState, protocolName: string) =
  var pn: seq[byte]
  for c in protocolName:
    pn.add(byte(c))

  if pn.len == HASHLEN:
    for i in 0..<HASHLEN:
      ss.h[i] = pn[i]
  else:
    ss.h = hash(pn)
  ss.ck = ss.h
  var zeros: array[KEYLEN, byte]
  ss.cs.initializeKey(zeros)

proc newSymmetricState(): SymmetricState =
  result = SymmetricState(cs: newCipherState())
  result.initializeSymmetric(PROTOCOL_NAME)

proc mixKey(ss: SymmetricState, inputKeyMaterial: openArray[byte]) =
  let outputs = hkdf(ss.ck, inputKeyMaterial, 2)
  for i in 0..<HASHLEN:
    ss.ck[i] = outputs[0][i]
  var key: array[KEYLEN, byte]
  copyMem(addr key[0], addr outputs[1][0], KEYLEN)
  ss.cs.initializeKey(key)

proc mixHash(ss: SymmetricState, data: openArray[byte]) =
  var input = newSeq[byte](ss.h.len + data.len)
  copyMem(addr input[0], unsafeAddr ss.h[0], ss.h.len)
  if data.len > 0:
    copyMem(addr input[ss.h.len], unsafeAddr data[0], data.len)
  ss.h = hash(input)

proc encryptAndHash(ss: SymmetricState, plaintext: openArray[byte]): seq[byte] =
  result = ss.cs.encrypt(ss.h, plaintext)
  ss.mixHash(result)

proc decryptAndHash(ss: SymmetricState, ciphertext: openArray[byte]): seq[byte] =
  result = ss.cs.decrypt(ss.h, ciphertext)
  ss.mixHash(ciphertext)

proc split(ss: SymmetricState): (CipherState, CipherState) =
  let outputs = hkdf(ss.ck, @[], 2)
  var k1, k2: array[KEYLEN, byte]
  copyMem(addr k1[0], addr outputs[0][0], KEYLEN)
  copyMem(addr k2[0], addr outputs[1][0], KEYLEN)
  let c1 = newCipherState()
  c1.initializeKey(k1)
  let c2 = newCipherState()
  c2.initializeKey(k2)
  (c1, c2)

type
  HandshakeState = ref object
    ss: SymmetricState
    initiator: bool
    e: KeyPair
    re: array[DHLEN, byte]
    messagePatterns: seq[seq[string]]

proc newHandshakeState(initiator: bool): HandshakeState =
  result = HandshakeState(
    ss: newSymmetricState(),
    initiator: initiator,
    messagePatterns: @[@["e"], @["e", "ee"]]
  )
  result.ss.mixHash(@[])

proc writeMessage(hs: HandshakeState, payload: openArray[byte]): (seq[byte], CipherState, CipherState) =
  if hs.messagePatterns.len == 0:
    raise newException(ValueError, "handshake complete")
  let pattern = hs.messagePatterns[0]
  hs.messagePatterns = hs.messagePatterns[1..^1]
  result[0] = @[]

  for token in pattern:
    case token
    of "e":
      hs.e = generateKeypair()
      result[0].add(hs.e.`public`)
      hs.ss.mixHash(hs.e.`public`)
    of "ee":
      let dhOut = dh(hs.e.private, hs.re)
      hs.ss.mixKey(dhOut)
    else:
      raise newException(ValueError, "unknown token: " & token)

  let ciphertext = hs.ss.encryptAndHash(payload)
  result[0].add(ciphertext)

  if hs.messagePatterns.len == 0:
    let (c1, c2) = hs.ss.split()
    if hs.initiator:
      return (result[0], c1, c2)
    else:
      return (result[0], c2, c1)

proc readMessage(hs: HandshakeState, message: openArray[byte]): (seq[byte], CipherState, CipherState) =
  if hs.messagePatterns.len == 0:
    raise newException(ValueError, "handshake complete")
  let pattern = hs.messagePatterns[0]
  hs.messagePatterns = hs.messagePatterns[1..^1]
  var pos = 0

  for token in pattern:
    case token
    of "e":
      if pos + DHLEN > message.len:
        raise newException(ValueError, "message too short")
      copyMem(addr hs.re[0], unsafeAddr message[pos], DHLEN)
      pos += DHLEN
      hs.ss.mixHash(hs.re)
    of "ee":
      let dhOut = dh(hs.e.private, hs.re)
      hs.ss.mixKey(dhOut)
    else:
      raise newException(ValueError, "unknown token: " & token)

  let ciphertext = message[pos..^1]
  let plaintext = hs.ss.decryptAndHash(ciphertext)

  if hs.messagePatterns.len == 0:
    let (c1, c2) = hs.ss.split()
    if hs.initiator:
      return (plaintext, c1, c2)
    else:
      return (plaintext, c2, c1)
  else:
    return (plaintext, nil, nil)

proc main() =
  # Simulate initiator
  let initiatorHS = newHandshakeState(true)
  let (msg1, _, _) = initiatorHS.writeMessage(@[])
  echo "Initiator sent message 1: ", msg1.toHex.toLowerAscii

  # Simulate responder
  let responderHS = newHandshakeState(false)
  let (payload1, _, _) = responderHS.readMessage(msg1)
  echo "Responder received payload 1: ", cast[string](payload1)

  let helloResponder = strToBytes("Hello from responder!")
  let (msg2, _, recvCSResp) = responderHS.writeMessage(helloResponder)
  echo "Responder sent message 2: ", msg2.toHex.toLowerAscii

  # Initiator processes message 2
  let (payload2, sendCSInit, _) = initiatorHS.readMessage(msg2)
  echo "Initiator received payload 2: ", cast[string](payload2)

  # Post-handshake: Initiator sends encrypted message to responder
  let message = strToBytes("Hello from initiator!")
  let ciphertext = sendCSInit.encrypt(@[], message)
  echo "Initiator encrypted: ", ciphertext.toHex.toLowerAscii

  # Responder decrypts
  let plaintext = recvCSResp.decrypt(@[], ciphertext)
  echo "Responder decrypted: ", cast[string](plaintext)

  echo "end of demo"
  echo "end of demo"

main()
