# Demonstration of the Noise KN handshake.

import std/[sysrand, strutils]
import stew/byteutils

import ../noise/utils
import ../noise/states

proc main() =
  echo "\n=== Noise KX Handshake Demo ==="
  # Simulate initiator with static keypair
  let initiatorKeypair = generateKeypair()
  let initiatorHS = newHandshakeState(true, "KX", s = initiatorKeypair)
  
  # Simulate responder with initiator's static public key
  let responderKeypair = generateKeypair()
  let responderHS = newHandshakeState(false, "KX", s = responderKeypair, rs = initiatorKeypair.`public`)
  
  # Initiator sends first message
  let (msg1, _, _) = initiatorHS.writeMessage(@[])
  echo "Initiator sent message 1: ", msg1.toHex.toLowerAscii

  # Responder processes first message
  let (payload1, _, _) = responderHS.readMessage(msg1)
  echo "Responder received payload 1: ", cast[string](payload1)

  # Responder sends response with payload
  let helloResponder = strToBytes("Hello from responder in KX!")
  let (msg2, sendCSResp, recvCSResp) = responderHS.writeMessage(helloResponder)
  echo "Responder sent message 2: ", msg2.toHex.toLowerAscii

  # Initiator processes response
  let (payload2, sendCSInit, recvCSInit) = initiatorHS.readMessage(msg2)
  echo "Initiator received payload 2: ", cast[string](payload2)

  # Post-handshake: Initiator sends encrypted message to responder
  echo "\n=== Post KX Handshake ==="
  let message = strToBytes("Hello from initiator in KX!")
  let ciphertext = sendCSInit.encrypt(@[], message)
  echo "Initiator encrypted: ", ciphertext.toHex.toLowerAscii

  # Responder decrypts
  let plaintext = recvCSResp.decrypt(@[], ciphertext)
  echo "Responder decrypted: ", cast[string](plaintext)

  # Post-handshake: Responder sends encrypted message to initiator
  let message2 = strToBytes("Hi from responder in KX!")
  let ciphertext2 = sendCSResp.encrypt(@[], message2)
  echo "Responder encrypted: ", ciphertext2.toHex.toLowerAscii

  # Initiator decrypts
  let plaintext2 = recvCSInit.decrypt(@[], ciphertext2)
  echo "Initiator decrypted: ", cast[string](plaintext2)

  echo "end of demo"

main()