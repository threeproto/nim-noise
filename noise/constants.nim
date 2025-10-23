# This file contains constants used in the Noise NN protocol implementation.

const
  DHLEN* = 32  # Length of Diffie-Hellman keys
  HASHLEN* = 32  # Length of hash outputs
  KEYLEN* = 32  # Length of symmetric keys
  MAXNONCE* = uint64.high  # Maximum nonce value to prevent overflow
  PROTOCOL_NAME* = "Noise_NN_25519_ChaChaPoly_SHA256"  # Protocol identifier