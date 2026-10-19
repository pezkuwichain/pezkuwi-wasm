# @pezkuwi/scure-sr25519

SR25519 cryptography for PezkuwiChain with **bizinikiwi** signing context.

Fork of [@scure/sr25519](https://github.com/paulmillr/scure-sr25519) with PezkuwiChain-specific signing context.

## Installation

```bash
npm install @pezkuwi/scure-sr25519
```

## Usage

```javascript
import { getPublicKey, sign, verify, secretFromSeed } from '@pezkuwi/scure-sr25519';

// Generate keypair from 32-byte seed
const secret = secretFromSeed(seed);
const publicKey = getPublicKey(secret);

// Sign message
const signature = sign(secret, message);

// Verify
const valid = verify(message, signature, publicKey);
```

## Difference from @scure/sr25519

`index.ts` is [@scure/sr25519 0.2.0](https://github.com/paulmillr/scure-sr25519/tree/0.2.0)
with three changes:

- the signing context is `bizinikiwi` instead of `substrate`
  (`BIZINIKIWI_CONTEXT`, used by `sign` and `verify`), so signatures match
  PezkuwiChain's runtime;
- the two header comment lines name Pezkuwi instead of Polkadot.

Nothing else differs; `lib/` is the TypeScript output of `index.ts`.

## Building

```bash
yarn build:scure-sr25519   # from the repository root; writes lib/
./scripts/check-scure-sr25519.sh   # CI: lib/ must equal a fresh build
```

## License

MIT. See [LICENSE](./LICENSE); the copyright notice is upstream's.
