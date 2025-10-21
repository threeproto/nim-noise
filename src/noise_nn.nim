import std/[sysrand, strutils]
import monocypher
import nimcrypto/sha2

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

proc generateKeypair(): KeyPair =
  result.private = urandom(DHLEN)
  crypto_x25519_public_key(result.`public`, result.private)

proc dh(priv: array[DHLEN, byte], pub: array[DHLEN, byte]): array[DHLEN, byte] =
  var shared: array[DHLEN, byte]
  crypto_x25519(shared, priv, pub)
  shared

proc hash(data: openArray[byte]): array[HASHLEN, byte] =
  var ctx: sha256
  ctx.init()
  ctx.update(data)
  ctx.finish(result)

proc hkdf(ck: openArray[byte], ikm: openArray[byte], numOutputs: int): seq[seq[byte]] =
  var okm = newSeq[byte](HASHLEN * numOutputs)
  hkdf[sha256](ikm, ck, @[], okm)
  result = @[]
  for i in 0..<numOutputs:
    let start = i * HASHLEN
    result.add(okm[start..<start + HASHLEN])

proc putLe64(buf: var openArray[byte], offset: int, value: uint64) =
  var v = value
  for i in 0..<8:
    buf[offset + i] = byte(v and 0xFF)
    v = v shr 8

proc aeadEncrypt(key: array[KEYLEN, byte], nonce: array[12, byte], ad, plaintext: openArray[byte]): seq[byte] =
  # Compute poly key
  var zeros: array[64, byte]
  crypto_chacha20_ietf(addr zeros, addr zeros, 64, key, nonce, 0)
  var polyKey: array[32, byte]
  copyMem(addr polyKey, addr zeros, 32)

  # Encrypt
  result = newSeq[byte](plaintext.len)
  if plaintext.len > 0:
    crypto_chacha20_ietf(addr result[0], unsafeAddr plaintext[0], plaintext.len, key, nonce, 1)

  # Compute mac
  let adPadLen = ((ad.len + 15) div 16) * 16
  let ctPadLen = ((result.len + 15) div 16) * 16
  let totalLen = adPadLen + ctPadLen + 16
  var input = newSeq[byte](totalLen)
  if ad.len > 0:
    copyMem(addr input[0], unsafeAddr ad[0], ad.len)
  # pads are zero by default
  let ctOffset = adPadLen
  if result.len > 0:
    copyMem(addr input[ctOffset], addr result[0], result.len)
  putLe64(input, totalLen - 16, uint64(ad.len))
  putLe64(input, totalLen - 8, uint64(result.len))

  var mac: array[16, byte]
  crypto_poly1305(mac, input, polyKey)

  result.add(mac)

proc aeadDecrypt(key: array[KEYLEN, byte], nonce: array[12, byte], ad, ciphertext: openArray[byte]): seq[byte] =
  if ciphertext.len < 16:
    raise newException(ValueError, "invalid ciphertext")
  let ctLen = ciphertext.len - 16
  let ct = ciphertext[0..<ctLen]
  let mac = ciphertext[ctLen..<ciphertext.len]

  # Compute poly key
  var zeros: array[64, byte]
  crypto_chacha20_ietf(addr zeros, addr zeros, 64, key, nonce, 0)
  var polyKey: array[32, byte]
  copyMem(addr polyKey, addr zeros, 32)

  # Compute expected mac
  let adPadLen = ((ad.len + 15) div 16) * 16
  let ctPadLen = ((ctLen + 15) div 16) * 16
  let totalLen = adPadLen + ctPadLen + 16
  var input = newSeq[byte](totalLen)
  if ad.len > 0:
    copyMem(addr input[0], unsafeAddr ad[0], ad.len)
  let ctOffset = adPadLen
  if ctLen > 0:
    copyMem(addr input[ctOffset], unsafeAddr ct[0], ctLen)
  putLe64(input, totalLen - 16, uint64(ad.len))
  putLe64(input, totalLen - 8, uint64(ctLen))

  var computedMac: array[16, byte]
  crypto_poly1305(computedMac, input, polyKey)

  if computedMac != array[16, byte](mac):
    raise newException(ValueError, "decryption failed")

  # Decrypt
  result = newSeq[byte](ctLen)
  if ctLen > 0:
    crypto_chacha20_ietf(addr result[0], unsafeAddr ct[0], ctLen, key, nonce, 1)

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
  cs.k != array[KEYLEN, byte]()

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

proc newSymmetricState(): SymmetricState =
  result = SymmetricState(cs: newCipherState())
  result.initializeSymmetric(PROTOCOL_NAME)

proc initializeSymmetric(ss: SymmetricState, protocolName: string) =
  let pn = protocolName.toOpenArrayByte(0, protocolName.high)
  if pn.len == HASHLEN:
    ss.h = cast[array[HASHLEN, byte]](pn)
  else:
    ss.h = hash(pn)
  ss.ck = ss.h
  ss.cs.initializeKey(array[KEYLEN, byte]())

proc mixKey(ss: SymmetricState, inputKeyMaterial: openArray[byte]) =
  let outputs = hkdf(ss.ck, inputKeyMaterial, 2)
  ss.ck = cast[array[HASHLEN, byte]](outputs[0])
  let key = cast[array[KEYLEN, byte]](outputs[1])
  ss.cs.initializeKey(key)

proc mixHash(ss: SymmetricState, data: openArray[byte]) =
  var input = newSeq[byte](ss.h.len + data.len)
  copyMem(addr input[0], unsafeAddr ss.h[0], ss.h.len)
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
  let k1 = cast[array[KEYLEN, byte]](outputs[0])
  let k2 = cast[array[KEYLEN, byte]](outputs[1])
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

  let helloResponder = "Hello from responder!".toOpenArrayByte(0, 20)
  let (msg2, _, recvCSResp) = responderHS.writeMessage(helloResponder)
  echo "Responder sent message 2: ", msg2.toHex.toLowerAscii

  # Initiator processes message 2
  let (payload2, sendCSInit, _) = initiatorHS.readMessage(msg2)
  echo "Initiator received payload 2: ", cast[string](payload2)

  # Post-handshake: Initiator sends encrypted message to responder
  let message = "Hello from initiator!".toOpenArrayByte(0, 20)
  let ciphertext = sendCSInit.encrypt(@[], message)
  echo "Initiator encrypted: ", ciphertext.toHex.toLowerAscii

  # Responder decrypts
  let plaintext = recvCSResp.decrypt(@[], ciphertext)
  echo "Responder decrypted: ", cast[string](plaintext)

main()
