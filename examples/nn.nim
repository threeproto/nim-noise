# Demonstration of the Noise NN handshake.

import std/[sysrand, strutils]
import stew/byteutils

import ../src/utils
import ../src/states

proc main() =
  # Simulate initiator
  let initiatorHS = newHandshakeState(true, "NN")
  let (msg1, _, _) = initiatorHS.writeMessage(@[])
  echo "Initiator sent message 1: ", msg1.toHex.toLowerAscii

  # Simulate responder
  let responderHS = newHandshakeState(false, "NN")
  let (payload1, _, _) = responderHS.readMessage(msg1)
  echo "Responder received payload 1: ", cast[string](payload1)

  let helloResponder = strToBytes("Hello from responder!")
  let (msg2, sendCSResp, recvCSResp) = responderHS.writeMessage(helloResponder)
  echo "Responder sent message 2: ", msg2.toHex.toLowerAscii

  # Initiator processes message 2
  let (payload2, sendCSInit, recvCSInit) = initiatorHS.readMessage(msg2)
  echo "Initiator received payload 2: ", cast[string](payload2)

  # Post-handshake: Initiator sends encrypted message to responder
  let message = strToBytes("Hello from initiator!")
  let ciphertext = sendCSInit.encrypt(@[], message)
  echo "Initiator encrypted: ", ciphertext.toHex.toLowerAscii

  # Responder decrypts
  let plaintext = recvCSResp.decrypt(@[], ciphertext)
  echo "Responder decrypted: ", cast[string](plaintext)

  # Post-handshake: Responder sends encrypted message to initiator
  let message2 = strToBytes("Hi from responder!")
  let ciphertext2 = sendCSResp.encrypt(@[], message2)
  echo "Responder encrypted: ", ciphertext2.toHex.toLowerAscii

  # Initiator decrypts
  let plaintext2 = recvCSInit.decrypt(@[], ciphertext2)
  echo "Initiator decrypted: ", cast[string](plaintext2)

  echo "end of demo"

main()