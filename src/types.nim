import ./constants

type
  KeyPair* = object
    private*: array[DHLEN, byte]  # Private key
    `public`*: array[DHLEN, byte]  # Public key

type HkdfResult*[len: static int] = array[len, byte]  # Result type for HKDF outputs
