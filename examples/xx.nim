# xx.nim
# Demonstration of the Noise XX handshake pattern.

import std/strutils

import stew/byteutils

import ../noise/utils
import ../noise/states

proc main() =
  let pattern = "XX"

  # Generate static keypairs for both parties
  let initiatorStatic = generateKeypair()
  let responderStatic = generateKeypair()

  # Simulate initiator
  let initiatorHS = newHandshakeState(true, pattern, s = initiatorStatic)
  let (msg1, _, _) = initiatorHS.writeMessage(@[])  # Message 1: e
  echo "Initiator sent message 1: ", msg1.toHex.toLowerAscii

  # Simulate responder
  let responderHS = newHandshakeState(false, pattern, s = responderStatic)
  let (payload1, _, _) = responderHS.readMessage(msg1)
  echo "Responder received payload 1: ", cast[string](payload1)

  let helloResponder = strToBytes("Hello from responder!")
  let (msg2, _, _) = responderHS.writeMessage(helloResponder)  # Message 2: e, ee, s, es + payload
  echo "Responder sent message 2: ", msg2.toHex.toLowerAscii

  # Initiator processes message 2
  let (payload2, _, _) = initiatorHS.readMessage(msg2)
  echo "Initiator received payload 2: ", cast[string](payload2)

  let helloInitiator = strToBytes("Hello from initiator!")
  let (msg3, sendCSInit, recvCSInit) = initiatorHS.writeMessage(helloInitiator)  # Message 3: s, se + payload
  echo "Initiator sent message 3: ", msg3.toHex.toLowerAscii

  # Responder processes message 3
  let (payload3, sendCSResp, recvCSResp) = responderHS.readMessage(msg3)
  echo "Responder received payload 3: ", cast[string](payload3)

  # Post-handshake: Initiator sends encrypted message to responder
  let message = strToBytes("Post-handshake from initiator!")
  let ciphertext = sendCSInit.encrypt(@[], message)
  echo "Initiator encrypted: ", ciphertext.toHex.toLowerAscii

  # Responder decrypts
  let plaintext = recvCSResp.decrypt(@[], ciphertext)
  echo "Responder decrypted: ", cast[string](plaintext)

  # Post-handshake: Responder sends encrypted message to initiator
  let message2 = strToBytes("Post-handshake from responder!")
  let ciphertext2 = sendCSResp.encrypt(@[], message2)
  echo "Responder encrypted: ", ciphertext2.toHex.toLowerAscii

  # Initiator decrypts
  let plaintext2 = recvCSInit.decrypt(@[], ciphertext2)
  echo "Initiator decrypted: ", cast[string](plaintext2)

  echo "end of demo"

main()
