# Tests for the Noise XX handshake pattern.

import unittest
import std/strutils
import stew/byteutils

import ../noise/utils
import ../noise/states

suite "Noise XX Handshake":

  setup:
    let pattern = "XX"
    # Generate static keypairs for both parties
    let initiatorStatic = generateKeypair()
    let responderStatic = generateKeypair()

    # Simulate initiator
    let initiatorHS = newHandshakeState(true, pattern, s = initiatorStatic)

    # Simulate responder
    let responderHS = newHandshakeState(false, pattern, s = responderStatic)

  test "Handshake completes successfully with empty initial payloads":
    let (msg1, _, _) = initiatorHS.writeMessage(@[])  # Message 1: e

    let (payload1, _, _) = responderHS.readMessage(msg1)
    check payload1.len == 0  # Expect empty payload

    let helloResponder = strToBytes("Hello from responder!")
    let (msg2, _, _) = responderHS.writeMessage(helloResponder)  # Message 2: e, ee, s, es + payload

    let (payload2, _, _) = initiatorHS.readMessage(msg2)
    check payload2 == helloResponder

    let helloInitiator = strToBytes("Hello from initiator!")
    let (msg3, _, _) = initiatorHS.writeMessage(helloInitiator)  # Message 3: s, se + payload

    let (payload3, _, _) = responderHS.readMessage(msg3)
    check payload3 == helloInitiator

  test "Responder sends payload in second message":
    let (msg1, _, _) = initiatorHS.writeMessage(@[])

    discard responderHS.readMessage(msg1)

    let helloResponder = strToBytes("Hello from responder!")
    let (msg2, _, _) = responderHS.writeMessage(helloResponder)

    let (payload2, _, _) = initiatorHS.readMessage(msg2)
    check payload2 == helloResponder

  test "Initiator sends payload in third message":
    let (msg1, _, _) = initiatorHS.writeMessage(@[])

    discard responderHS.readMessage(msg1)

    let helloResponder = strToBytes("Hello from responder!")
    let (msg2, _, _) = responderHS.writeMessage(helloResponder)

    discard initiatorHS.readMessage(msg2)

    let helloInitiator = strToBytes("Hello from initiator!")
    let (msg3, _, _) = initiatorHS.writeMessage(helloInitiator)

    let (payload3, _, _) = responderHS.readMessage(msg3)
    check payload3 == helloInitiator

  test "Post-handshake encryption from initiator to responder":
    let (msg1, _, _) = initiatorHS.writeMessage(@[])

    discard responderHS.readMessage(msg1)

    let helloResponder = strToBytes("Hello from responder!")
    let (msg2, _, _) = responderHS.writeMessage(helloResponder)

    discard initiatorHS.readMessage(msg2)

    let helloInitiator = strToBytes("Hello from initiator!")
    let (msg3, sendCSInit, recvCSInit) = initiatorHS.writeMessage(helloInitiator)

    let (payload3, sendCSResp, recvCSResp) = responderHS.readMessage(msg3)

    let message = strToBytes("Post-handshake from initiator!")
    let ciphertext = sendCSInit.encrypt(@[], message)
    let plaintext = recvCSResp.decrypt(@[], ciphertext)
    check plaintext == message

  test "Post-handshake encryption from responder to initiator":
    let (msg1, _, _) = initiatorHS.writeMessage(@[])

    discard responderHS.readMessage(msg1)

    let helloResponder = strToBytes("Hello from responder!")
    let (msg2, _, _) = responderHS.writeMessage(helloResponder)

    discard initiatorHS.readMessage(msg2)

    let helloInitiator = strToBytes("Hello from initiator!")
    let (msg3, sendCSInit, recvCSInit) = initiatorHS.writeMessage(helloInitiator)

    let (payload3, sendCSResp, recvCSResp) = responderHS.readMessage(msg3)

    let message2 = strToBytes("Post-handshake from responder!")
    let ciphertext2 = sendCSResp.encrypt(@[], message2)
    let plaintext2 = recvCSInit.decrypt(@[], ciphertext2)
    check plaintext2 == message2