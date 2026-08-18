#!/usr/bin/env sh
set -eu
# Prints a non-secret fingerprint so an operator can confirm which seed is loaded without
# the seed itself ever reaching a terminal, a log, or a CI transcript.
node -e 'const {mnemonicFingerprint}=require("./dist/wallet");
         const b=Buffer.from(process.env.MNEMONIC||"","utf8");
         if(!b.length){console.error("no seed loaded");process.exit(1)}
         console.log("seed fingerprint:", mnemonicFingerprint(b));'
