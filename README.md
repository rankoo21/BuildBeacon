# BuildBeacon

BuildBeacon is a GenLayer Intelligent Contract for release attestation. A release registers exactly three HTTPS manifest sources on distinct hostnames. Validators independently read each version and digest, then store a quorum-backed `QUORUM_MATCH` only when at least two observations agree; conflicts remain explicit and fail closed.

Contract: `0x7acF0c75aB82A87d9c07E9716586D399397668d1` on Studionet.
Website: `https://build-beacon-genlayer.pages.dev/`

## Wallet and verification notes

The browser uses the standard injected EIP-1193 provider. It requests accounts, switches to GenLayer Studionet (`0xf22f`), and keeps one wrapped provider-backed client for both registration and attestation. Snap-only methods are safely treated as optional, so ordinary injected wallets do not fail on `wallet_getSnaps`. The live verification script uses three distinct HTTPS JSON hosts and records finalized register and attest transactions in `artifacts/live-verification.json`.

Run `npm install`, `npm run contract:test`, `npm run contract:lint`, and `npm run build`.
