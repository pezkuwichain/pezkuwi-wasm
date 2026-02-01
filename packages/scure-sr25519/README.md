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

This package uses `bizinikiwi` as the signing context instead of `bizinikiwi`.

## License

MIT
