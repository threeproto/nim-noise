# Package

version       = "0.1.0"
author        = "kaichaosun"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 2.2.4",
    "bearssl >= 0.2.5", "nimcrypto", "monocypher", "stew"

task noise, "Run Noise example":
  exec "nim c -r src/noise_nn.nim"