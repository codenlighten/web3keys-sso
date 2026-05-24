# Web3Keys

Noncustodial BSV identity wallet — "Sign in with Web3Keys" SSO with biometric ECDSA signing.

The user's secp256k1 identity key lives only on their device, encrypted at rest, gated by a platform biometric via WebAuthn PRF. A password fallback is always present. BIP39 mnemonic is the recovery root.

## Run locally

```
npm install
npm start
```

Then open http://localhost:8787 (WebAuthn permits `localhost` as the rpId for dev).

## Status

Phase 1 (vault + biometric unlock + sign message) is in. Phases 2–5: more signing capabilities, SSO popup, server features, recovery polish.
