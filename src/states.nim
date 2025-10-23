# This file combines the definitions and procedures for CipherState, SymmetricState, and HandshakeState.

import ./constants
import ./types
import ./utils
import ./hkdf

# Forward declarations for states
type
  CipherState* = ref object
    k*: array[KEYLEN, byte]  # Symmetric key
    n*: uint64  # Nonce counter

  SymmetricState* = ref object
    cs*: CipherState  # Associated cipher state
    ck*: array[HASHLEN, byte]  # Chaining key
    h*: array[HASHLEN, byte]  # Handshake hash

  HandshakeState* = ref object
    ss*: SymmetricState  # Symmetric state
    initiator*: bool  # Whether this is the initiator
    e*: KeyPair  # Ephemeral keypair
    re*: array[DHLEN, byte]  # Remote ephemeral public key
    messagePatterns*: seq[seq[string]]  # Remaining message patterns

# CipherState handles symmetric encryption/decryption with nonce management.

# Create a new CipherState
proc newCipherState*(): CipherState =
  CipherState(n: 0)

# Initialize the key in the CipherState
proc initializeKey*(cs: CipherState, key: array[KEYLEN, byte]) =
  cs.k = key
  cs.n = 0

# Check if the CipherState has a key set
proc hasKey*(cs: CipherState): bool =
  var zeros: array[KEYLEN, byte]
  cs.k != zeros

# Encrypt with associated data
proc encrypt*(cs: CipherState, ad, plaintext: openArray[byte]): seq[byte] =
  if not cs.hasKey():
    return @plaintext
  if cs.n > MAXNONCE:
    raise newException(ValueError, "nonce overflow")
  var nonce: array[12, byte]
  putLe64(nonce, 4, cs.n)
  result = aeadEncrypt(cs.k, nonce, ad, plaintext)
  cs.n.inc

# Decrypt with associated data
proc decrypt*(cs: CipherState, ad, ciphertext: openArray[byte]): seq[byte] =
  if not cs.hasKey():
    return @ciphertext
  if cs.n > MAXNONCE:
    raise newException(ValueError, "nonce overflow")
  var nonce: array[12, byte]
  putLe64(nonce, 4, cs.n)
  result = aeadDecrypt(cs.k, nonce, ad, ciphertext)
  cs.n.inc

# SymmetricState manages the handshake hash, chaining key, and cipher operations.

# Initialize SymmetricState with protocol name
proc initializeSymmetric*(ss: SymmetricState, protocolName: string) =
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

# Create a new SymmetricState
proc newSymmetricState*(): SymmetricState =
  result = SymmetricState(cs: newCipherState())
  result.initializeSymmetric(PROTOCOL_NAME)

# Mix key material into the chaining key and update cipher key
proc mixKey*(ss: SymmetricState, inputKeyMaterial: openArray[byte]) =
  let outputs = hkdf(ss.ck, inputKeyMaterial, 2)
  for i in 0..<HASHLEN:
    ss.ck[i] = outputs[0][i]
  var key: array[KEYLEN, byte]
  copyMem(addr key[0], addr outputs[1][0], KEYLEN)
  ss.cs.initializeKey(key)

# Mix data into the handshake hash
proc mixHash*(ss: SymmetricState, data: openArray[byte]) =
  var input = newSeq[byte](ss.h.len + data.len)
  copyMem(addr input[0], unsafeAddr ss.h[0], ss.h.len)
  if data.len > 0:
    copyMem(addr input[ss.h.len], unsafeAddr data[0], data.len)
  ss.h = hash(input)

# Encrypt and mix the ciphertext into the hash
proc encryptAndHash*(ss: SymmetricState, plaintext: openArray[byte]): seq[byte] =
  result = ss.cs.encrypt(ss.h, plaintext)
  ss.mixHash(result)

# Decrypt and mix the ciphertext into the hash
proc decryptAndHash*(ss: SymmetricState, ciphertext: openArray[byte]): seq[byte] =
  result = ss.cs.decrypt(ss.h, ciphertext)
  ss.mixHash(ciphertext)

# Split into two CipherStates for transport
proc split*(ss: SymmetricState): (CipherState, CipherState) =
  let outputs = hkdf(ss.ck, @[], 2)
  var k1, k2: array[KEYLEN, byte]
  copyMem(addr k1[0], addr outputs[0][0], KEYLEN)
  copyMem(addr k2[0], addr outputs[1][0], KEYLEN)
  let c1 = newCipherState()
  c1.initializeKey(k1)
  let c2 = newCipherState()
  c2.initializeKey(k2)
  (c1, c2)

# HandshakeState manages the Noise NN handshake process.

# Create a new HandshakeState
proc newHandshakeState*(initiator: bool): HandshakeState =
  result = HandshakeState(
    ss: newSymmetricState(),
    initiator: initiator,
    messagePatterns: @[@["e"], @["e", "ee"]]
  )
  result.ss.mixHash(@[])

# Write a handshake message
proc writeMessage*(hs: HandshakeState, payload: openArray[byte]): (seq[byte], CipherState, CipherState) =
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

# Read a handshake message
proc readMessage*(hs: HandshakeState, message: openArray[byte]): (seq[byte], CipherState, CipherState) =
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