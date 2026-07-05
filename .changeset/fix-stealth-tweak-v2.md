---
"@specterpq/sdk": major
---

Fix stealth-address derivation to match the SPECTER backend.

The tweak scalar was derived with the `SPECTER_STEALTH_TWEAK_V1` domain, the
bare shared secret as hash input, and modular reduction. The backend (which
computes the address the sender actually funds) uses `SPECTER_STEALTH_TWEAK_V2`,
hashes `shared_secret || counter`, and selects the scalar by rejection
sampling. The two produced completely different addresses, so scanning
resolved every payment to an unfunded address — balances read as empty and any
exported private key controlled the wrong (empty) account.

`tweak_scalar` now matches the backend byte-for-byte, locked in by a
cross-implementation known-answer test. Addresses returned by
`deriveStealthPublic` / `deriveStealthKeys` change; anyone on an older version
must upgrade to discover and spend real funds. No funds were ever lost — they
sit at the backend-derived addresses and become visible again after upgrade.
