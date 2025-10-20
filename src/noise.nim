import std/[sequtils, options, strutils]
import nimcrypto/[blake2, hmac, chacha20poly1305, x25519]

# -----------------------------
# Constants
# -----------------------------

const
  DHLEN* = 32
  HASHLEN* = 32
  MACLEN* = 16
  NONCELEN* = 12
  TAGLEN* = 16
  BLOCKLEN* = 64

  EMPTY_HASH* = newSeq[byte](HASHLEN)
  EMPTY_KEY* = newSeq[byte](DHLEN)

# -----------------------------
# Error and Types
# -----------------------------

type
  NoiseError* = enum
    DecryptionError,
    InvalidKeyError,
    InvalidStateError,
    HandshakeNotCompleteError

  Key* = array[DHLEN, byte]
  PublicKey* = array[DHLEN, byte]
  Nonce* = uint64
  Hash* = array[HASHLEN, byte]

  Keypair* = object
    priv*: Key
    pub*: PublicKey

# -----------------------------
# Utility Functions
# -----------------------------

proc toNonce*(n: uint64): array[NONCELEN, byte] =
  var out: array[NONCELEN, byte]
  # Noise uses 96-bit nonce with leading zeros
  for i in 0..<8:
    out[4 + i] = byte((n shr (8 * i)) and 0xff)
  return out

proc dh*(priv: Key, pub: PublicKey): seq[byte] =
  var shared: array[DHLEN, byte]
  if not x25519(shared, priv, pub):
    raise newException(ValueError, "Invalid Curve25519 key")
  result = @shared

proc generateKeypair*(): Keypair =
  var priv, pub: array[32, byte]
  x25519_keypair(pub, priv)
  result.priv = priv
  result.pub = pub

proc eqBytes*(a, b: openArray[byte]): bool =
  if a.len != b.len: return false
  var diff = 0
  for i in 0..<a.len:
    diff = diff or (a[i] xor b[i])
  return diff == 0

# -----------------------------
# Crypto Primitives
# -----------------------------

proc hash*(input: openArray[byte]): Hash =
  var ctx: Blake2s
  ctx.init()
  ctx.update(input)
  ctx.finish(result)

proc hmac*(key, data: openArray[byte]): Hash =
  var mac: HMAC[Blake2s]
  mac.init(key)
  mac.update(data)
  mac.finish(result)

proc hkdf*(ck, ikm: openArray[byte]): (Hash, Hash) =
  let tempKey = hmac(ck, ikm)
  let out1 = hmac(tempKey, @[1'u8])
  let out2 = hmac(tempKey, out1.toSeq() & @[2'u8])
  return (out1, out2)

proc encrypt*(key: openArray[byte], nonce: uint64, ad, plaintext: openArray[byte]): seq[byte] =
  var ctx: ChaCha20Poly1305
  var tag: array[TAGLEN, byte]
  var out = newSeq[byte](plaintext.len)
  let n = toNonce(nonce)
  ctx.init(key)
  ctx.aadUpdate(ad)
  ctx.encrypt(out, plaintext, n)
  ctx.final(tag)
  ctx.clear()
  result = out & tag

proc decrypt*(key: openArray[byte], nonce: uint64, ad, ciphertext: openArray[byte]): Option[seq[byte]] =
  if ciphertext.len < TAGLEN:
    return none(seq[byte])
  let n = toNonce(nonce)
  let data = ciphertext[0 ..< ciphertext.len - TAGLEN]
  let tag = ciphertext[^TAGLEN .. ^1]
  var ctx: ChaCha20Poly1305
  var out = newSeq[byte](data.len)
  ctx.init(key)
  ctx.aadUpdate(ad)
  if not ctx.decrypt(out, data, tag, n):
    return none(seq[byte])
  ctx.clear()
  return some(out)

# -----------------------------
# CipherState
# -----------------------------

type
  CipherState* = object
    k*: Key
    n*: Nonce

proc initCipherState*(k: Key): CipherState =
  result.k = k
  result.n = 0

proc encryptWithAd*(cs: var CipherState, ad, plaintext: openArray[byte]): seq[byte] =
  let out = encrypt(cs.k, cs.n, ad, plaintext)
  cs.n.inc()
  return out

proc decryptWithAd*(cs: var CipherState, ad, ciphertext: openArray[byte]): Option[seq[byte]] =
  let out = decrypt(cs.k, cs.n, ad, ciphertext)
  if out.isSome(): cs.n.inc()
  return out

# -----------------------------
# SymmetricState
# -----------------------------

type
  SymmetricState* = object
    cs*: CipherState
    ck*: Hash
    h*: Hash

proc initSymmetricState*(protoName: string): SymmetricState =
  var pname = protoName.toBytes()
  if pname.len <= HASHLEN:
    result.h = pname & newSeq[byte](HASHLEN - pname.len)
  else:
    result.h = hash(pname)
  result.ck = result.h
  result.cs = initCipherState(EMPTY_KEY)

proc mixKey*(ss: var SymmetricState, input: openArray[byte]) =
  let (ck, tempK) = hkdf(ss.ck, input)
  ss.ck = ck
  ss.cs.k = tempK

proc mixHash*(ss: var SymmetricState, data: openArray[byte]) =
  ss.h = hash(ss.h.toSeq() & data.toSeq())

proc split*(ss: SymmetricState): (CipherState, CipherState) =
  let (k1, k2) = hkdf(ss.ck, [])
  (initCipherState(k1), initCipherState(k2))

# -----------------------------
# HandshakeState
# -----------------------------

type
  HandshakeState* = object
    ss*: SymmetricState
    s*: Keypair
    e*: Keypair
    rs*: PublicKey
    re*: PublicKey
    initiator*: bool

# Write message A (initiator -> responder): sends ephemeral key
proc writeMessageA*(hs: var HandshakeState): seq[byte] =
  hs.e = generateKeypair()
  hs.ss.mixHash(hs.e.pub)
  result = hs.e.pub.toSeq()

# Read message A (responder <- initiator)
proc readMessageA*(hs: var HandshakeState, msg: openArray[byte]) =
  if msg.len != DHLEN: raise newException(ValueError, "Invalid message A length")
  hs.re = msg.toArray(DHLEN)
  hs.ss.mixHash(hs.re)

# Write message B (responder -> initiator): sends ephemeral key and encrypted payloads
proc writeMessageB*(hs: var HandshakeState): seq[byte] =
  hs.e = generateKeypair()
  var buf = hs.e.pub.toSeq()
  hs.ss.mixHash(hs.e.pub)

  # ee = DH(e, re)
  var ee = dh(hs.e.priv, hs.re)
  hs.ss.mixKey(ee)

  # se = DH(s, re)
  var se = dh(hs.s.priv, hs.re)
  hs.ss.mixKey(se)

  # encrypt static public key under new key
  let enc = hs.ss.cs.encryptWithAd(hs.ss.h, hs.s.pub)
  hs.ss.mixHash(enc)
  buf.add(enc)
  return buf

# Read message B (initiator <- responder)
proc readMessageB*(hs: var HandshakeState, msg: openArray[byte]) =
  if msg.len < DHLEN + MACLEN: raise newException(ValueError, "Invalid message B")
  hs.re = msg[0 ..< DHLEN].toArray(DHLEN)
  hs.ss.mixHash(hs.re)

  let enc = msg[DHLEN .. ^1]
  let dec = hs.ss.cs.decryptWithAd(hs.ss.h, enc)
  if dec.isNone(): raise newException(ValueError, "Decryption failed")
  hs.rs = dec.get().toArray(DHLEN)
  hs.ss.mixHash(enc)

  # Compute shared keys
  let ee = dh(hs.e.priv, hs.re)
  hs.ss.mixKey(ee)
  let se = dh(hs.e.priv, hs.rs)
  hs.ss.mixKey(se)

# -----------------------------
# NoiseSession
# -----------------------------

type
  NoiseSession* = object
    hs*: HandshakeState
    cs1*: CipherState
    cs2*: CipherState
    h*: Hash
    isTransport*: bool
    initiator*: bool

proc initNoiseSession*(initiator: bool, s: Keypair, rs: PublicKey): NoiseSession =
  var proto = "Noise_KN_25519_ChaChaPoly_BLAKE2s"
  var ss = initSymmetricState(proto)
  ss.mixHash(rs)
  result.hs = HandshakeState(ss: ss, s: s, rs: rs, initiator: initiator)
  result.initiator = initiator
  result.isTransport = false

proc handshakeWrite*(sess: var NoiseSession): seq[byte] =
  if sess.initiator:
    return sess.hs.writeMessageA()
  else:
    return sess.hs.writeMessageB()

proc handshakeRead*(sess: var NoiseSession, msg: openArray[byte]) =
  if sess.initiator:
    sess.hs.readMessageB(msg)
  else:
    sess.hs.readMessageA(msg)

proc splitSession*(sess: var NoiseSession) =
  let (cs1, cs2) = sess.hs.ss.split()
  if sess.initiator:
    sess.cs1 = cs1
    sess.cs2 = cs2
  else:
    sess.cs1 = cs2
    sess.cs2 = cs1
  sess.isTransport = true

# -----------------------------
# Example Usage
# -----------------------------
when isMainModule:
  let serverStatic = generateKeypair()
  let clientStatic = generateKeypair()

  var client = initNoiseSession(true, clientStatic, serverStatic.pub)
  var server = initNoiseSession(false, serverStatic, EMPTY_KEY)

  let msgA = client.handshakeWrite()
  server.handshakeRead(msgA)

  let msgB = server.handshakeWrite()
  client.handshakeRead(msgB)

  client.splitSession()
  server.splitSession()

  echo "Handshake complete ✅"
  echo "Client key 1: ", client.cs1.k
  echo "Server key 1: ", server.cs2.k
