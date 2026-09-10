#!/usr/bin/env bash
# Probe helper (S19): behaves as the real cosign except that signing a bundle
# manifest fails. Records still sign, sessions still run, the bundle is still
# created — and then sign-blob over manifest.json exits 1. This exercises the
# post-packet failure path, not just startup.
if [ "$1" = "sign-blob" ]; then
  for a in "$@"; do
    case "$a" in
      */manifest.json)
        echo "fake-cosign: refusing to sign $a (simulated cosign sign-blob failure)" >&2
        exit 1;;
    esac
  done
fi
exec cosign "$@"
