# @pezkuwi/wasm-crypto

WASM cryptographic primitives for PezkuwiChain.

## Overview

This package provides WebAssembly-based cryptographic functions used by PezkuwiChain applications, including:

- **SR25519** - Schnorr signatures with Ristretto point compression (bizinikiwi signing context)
- **ED25519** - Edwards-curve Digital Signature Algorithm
- **BIP39** - Mnemonic code for generating deterministic keys
- **Hashing** - Blake2b, SHA256, SHA512, Keccak, XXHash, Scrypt, PBKDF2

## Installation

```bash
npm install @pezkuwi/wasm-crypto
# or
yarn add @pezkuwi/wasm-crypto
```

## Usage

```javascript
import { waitReady, sr25519KeypairFromSeed, sr25519Sign } from '@pezkuwi/wasm-crypto';

// Initialize WASM
await waitReady();

// Generate keypair from seed
const seed = new Uint8Array(32); // your seed here
const keypair = sr25519KeypairFromSeed(seed);

// Sign a message
const publicKey = keypair.slice(64);
const secretKey = keypair.slice(0, 64);
const message = new TextEncoder().encode('Hello PezkuwiChain!');
const signature = sr25519Sign(publicKey, secretKey, message);
```

## Packages

| Package | Description |
|---------|-------------|
| `@pezkuwi/wasm-crypto` | Main package with all crypto functions |
| `@pezkuwi/wasm-crypto-wasm` | Compiled WASM binary |
| `@pezkuwi/wasm-crypto-asmjs` | ASM.js fallback for older browsers |
| `@pezkuwi/wasm-crypto-init` | Initialization helpers |
| `@pezkuwi/wasm-bridge` | WASM bridge utilities |
| `@pezkuwi/wasm-util` | Utility functions |

## Building from Source

```bash
# Install dependencies
yarn install

# Build WASM and JavaScript
yarn build

# Run tests
yarn test
```

### Prerequisites

- Node.js 18+
- Rust toolchain (for WASM compilation)
- wasm-pack

## Signing Context

This package uses **bizinikiwi** as the SR25519 signing context, which is unique to PezkuwiChain. This ensures signature incompatibility with other networks for security.

## License

Apache-2.0
