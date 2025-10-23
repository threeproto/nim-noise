# Tests for the Noise NN handshake pattern.

import unittest
import std/[sysrand, strutils]
import stew/byteutils

import ../noise/utils
import ../noise/states

suite "Noise NN Handshake":

  test "Handshake completes successfully with empty initial payloads":
    let initiatorHS = newHandshakeState(true, "NN")
    let (msg1, _, _) = initiatorHS.writeMessage(@[])

    let responderHS = newHandshakeState(false, "NN")
    let (payload1, _, _) = responderHS.readMessage(msg1)
    check payload1.len == 0  # Expect empty payload

  test "Responder sends payload in second message":
    let initiatorHS = newHandshakeState(true, "NN")
    let (msg1, _, _) = initiatorHS.writeMessage(@[])

    let responderHS = newHandshakeState(false, "NN")
    discard responderHS.readMessage(msg1)

    let helloResponder = strToBytes("Hello from responder!")
    let (msg2, _, _) = responderHS.writeMessage(helloResponder)

    let (payload2, _, _) = initiatorHS.readMessage(msg2)
    check payload2 == helloResponder

  test "Post-handshake encryption from initiator to responder":
    let initiatorHS = newHandshakeState(true, "NN")
    let (msg1, _, _) = initiatorHS.writeMessage(@[])

    let responderHS = newHandshakeState(false, "NN")
    discard responderHS.readMessage(msg1)

    let helloResponder = strToBytes("Hello from responder!")
    let (msg2, sendCSResp, recvCSResp) = responderHS.writeMessage(helloResponder)

    let (payload2, sendCSInit, recvCSInit) = initiatorHS.readMessage(msg2)

    let message = strToBytes("Hello from initiator!")
    let ciphertext = sendCSInit.encrypt(@[], message)
    let plaintext = recvCSResp.decrypt(@[], ciphertext)
    check plaintext == message

  test "Post-handshake encryption from responder to initiator":
    let initiatorHS = newHandshakeState(true, "NN")
    let (msg1, _, _) = initiatorHS.writeMessage(@[])

    let responderHS = newHandshakeState(false, "NN")
    discard responderHS.readMessage(msg1)

    let helloResponder = strToBytes("Hello from responder!")
    let (msg2, sendCSResp, recvCSResp) = responderHS.writeMessage(helloResponder)

    let (payload2, sendCSInit, recvCSInit) = initiatorHS.readMessage(msg2)

    let message2 = strToBytes("Hi from responder!")
    let ciphertext2 = sendCSResp.encrypt(@[], message2)
    let plaintext2 = recvCSInit.decrypt(@[], ciphertext2)
    check plaintext2 == message2