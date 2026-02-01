// Test the built package
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

// Load the built bundle
const bundle = await import('./packages/wasm-crypto/build/bundle.js');

console.log('=== Testing Built Bundle ===');
console.log('Available exports:', Object.keys(bundle));

// Wait for WASM to initialize
console.log('\nInitializing WASM...');
const ready = await bundle.waitReady();
console.log('WASM ready:', ready);

if (ready) {
  // Test signing context
  console.log('\n--- Testing getSigningContext ---');
  const context = bundle.getSigningContext();
  console.log('Signing context:', context);

  if (context === 'bizinikiwi') {
    console.log('BIZINIKIWI CONFIRMED!');
  } else {
    console.log('WARNING: Expected "bizinikiwi" but got:', context);
  }

  // Test sr25519KeypairFromSeed
  console.log('\n--- Testing sr25519KeypairFromSeed ---');
  const seed = new Uint8Array([
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
  ]);

  const keypair = bundle.sr25519KeypairFromSeed(seed);
  const secretKey = keypair.slice(0, 64);
  const publicKey = keypair.slice(64, 96);

  console.log('Keypair length:', keypair.length);
  console.log('Public key:', Buffer.from(publicKey).toString('hex'));

  // Test sr25519Sign
  console.log('\n--- Testing sr25519Sign ---');
  const message = new TextEncoder().encode('test message');
  const signature = bundle.sr25519Sign(publicKey, secretKey, message);
  console.log('Signature:', Buffer.from(signature).toString('hex').slice(0, 64) + '...');

  // Test sr25519Verify
  console.log('\n--- Testing sr25519Verify ---');
  const verified = bundle.sr25519Verify(signature, message, publicKey);
  console.log('Verification:', verified ? 'SUCCESS' : 'FAILED');

  if (verified) {
    console.log('\n=======================================');
    console.log('BIZINIKIWI WASM PACKAGE WORKING!');
    console.log('=======================================');
  }
} else {
  console.log('FAILED to initialize WASM');
}
