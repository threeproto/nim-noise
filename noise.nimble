# Package

packageName   = "noise"
version       = "0.1.0"
author        = "kaichaosun"
description   = "A new awesome nimble package"
license       = "MIT"


# Dependencies

requires "nim >= 2.2.4",
    "bearssl >= 0.2.5", "nimcrypto", "monocypher", "stew"

task nn, "Run Noise NN pattern":
  exec "nim c -r examples/nn.nim"

task xx, "Run Noise XX pattern":
  exec "nim c -r examples/xx.nim"

task kn, "Run Noise KN pattern":
  exec "nim c -r examples/kn.nim"

task kx, "Run Noise KX pattern":
  exec "nim c -r examples/kx.nim"