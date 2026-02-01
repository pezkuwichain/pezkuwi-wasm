// Direct test without going through npm package resolution
import zlib from 'zlib';

// Load bytes directly from the source
const bytesModule = await import('./packages/wasm-crypto-wasm/src/cjs/bytes.js');
const { bytes, lenIn, lenOut } = bytesModule;

console.log('=== Testing Bizinikiwi WASM Directly ===');
console.log('Compressed size:', lenIn);
console.log('Uncompressed size:', lenOut);

// Decompress
const compressed = Buffer.from(bytes, 'base64');
const wasmBytes = zlib.inflateSync(compressed);
console.log('WASM size:', wasmBytes.length);

// Check import module name
const wasmStr = wasmBytes.toString('utf8', 0, 500);
const moduleNameMatch = wasmStr.match(/pezkuwi_wasm_crypto_bg\.js/);
if (moduleNameMatch) {
  console.log('Import module: ./pezkuwi_wasm_crypto_bg.js (bizinikiwi WASM confirmed!)');
} else {
  console.log('Import module: NOT bizinikiwi WASM');
  process.exit(1);
}

// WASM helpers
let wasm = null;
let cachedUint8ArrayMemory = null;
let cachedTextDecoder = null;
let WASM_VECTOR_LEN = 0;

function getUint8ArrayMemory() {
  if (cachedUint8ArrayMemory === null || cachedUint8ArrayMemory.byteLength === 0) {
    cachedUint8ArrayMemory = new Uint8Array(wasm['memory'].buffer);
  }
  return cachedUint8ArrayMemory;
}

function getStringFromWasm(ptr, len) {
  if (!cachedTextDecoder) {
    cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
  }
  ptr = ptr >>> 0;
  return cachedTextDecoder.decode(getUint8ArrayMemory().subarray(ptr, ptr + len));
}

function getArrayU8FromWasm(ptr, len) {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory().subarray(ptr / 1, ptr / 1 + len);
}

function passArray8ToWasm(arg, malloc) {
  const ptr = malloc(arg.length * 1, 1) >>> 0;
  getUint8ArrayMemory().set(arg, ptr / 1);
  WASM_VECTOR_LEN = arg.length;
  return ptr;
}

function addToExternrefTable(obj) {
  const idx = wasm['__externref_table_alloc']();
  wasm['__wbindgen_externrefs'].set(idx, obj);
  return idx;
}

function takeFromExternrefTable(idx) {
  const value = wasm['__wbindgen_externrefs'].get(idx);
  wasm['__externref_table_dealloc'](idx);
  return value;
}

function isLikeNone(x) {
  return x === undefined || x === null;
}

function handleError(f, args) {
  try {
    return f.apply(null, args);
  } catch (e) {
    const idx = addToExternrefTable(e);
    wasm['__wbindgen_exn_store'](idx);
    return undefined;
  }
}

// WASM imports
import crypto from 'crypto';

const import0 = {
  __wbg___wbindgen_is_function_0095a73b8b156f76: (arg0) => typeof(arg0) === 'function',
  __wbg___wbindgen_is_object_5ae8e5880f2c1fbd: (arg0) => typeof(arg0) === 'object' && arg0 !== null,
  __wbg___wbindgen_is_string_cd444516edc5b180: (arg0) => typeof(arg0) === 'string',
  __wbg___wbindgen_is_undefined_9e4d92534c42d778: (arg0) => arg0 === undefined,
  __wbg___wbindgen_throw_be289d5034ed271b: (arg0, arg1) => { throw new Error(getStringFromWasm(arg0, arg1)); },
  __wbg_call_389efe28435a9388: function() { return handleError((arg0, arg1) => arg0.call(arg1), arguments); },
  __wbg_call_4708e0c13bdc8e95: function() { return handleError((arg0, arg1, arg2) => arg0.call(arg1, arg2), arguments); },
  __wbg_crypto_86f2631e91b51511: (arg0) => arg0.crypto,
  __wbg_getRandomValues_b3f15fcbfabb0f8b: function() { return handleError((arg0, arg1) => arg0.getRandomValues(arg1), arguments); },
  __wbg_length_32ed9a279acd054c: (arg0) => arg0.length,
  __wbg_msCrypto_d562bbe83e0d4b91: (arg0) => arg0.msCrypto,
  __wbg_new_no_args_1c7c842f08d00ebb: (arg0, arg1) => new Function(getStringFromWasm(arg0, arg1)),
  __wbg_new_with_length_a2c39cbe88fd8ff1: (arg0) => new Uint8Array(arg0 >>> 0),
  __wbg_node_e1f24f89a7336c2e: (arg0) => arg0.node,
  __wbg_process_3975fd6c72f520aa: (arg0) => arg0.process,
  __wbg_prototypesetcall_bdcdcc5842e4d77d: (arg0, arg1, arg2) => Uint8Array.prototype.set.call(getArrayU8FromWasm(arg0, arg1), arg2),
  __wbg_randomFillSync_f8c153b79f285817: function() { return handleError((arg0, arg1) => arg0.randomFillSync(arg1), arguments); },
  __wbg_require_b74f47fc2d022fd6: function() { return handleError(() => module.require, arguments); },
  __wbg_static_accessor_GLOBAL_12837167ad935116: () => isLikeNone(global) ? 0 : addToExternrefTable(global),
  __wbg_static_accessor_GLOBAL_THIS_e628e89ab3b1c95f: () => isLikeNone(globalThis) ? 0 : addToExternrefTable(globalThis),
  __wbg_static_accessor_SELF_a621d3dfbb60d0ce: () => isLikeNone(typeof self === 'undefined' ? null : self) ? 0 : addToExternrefTable(self),
  __wbg_static_accessor_WINDOW_f8727f0cf888e0bd: () => isLikeNone(typeof window === 'undefined' ? null : window) ? 0 : addToExternrefTable(window),
  __wbg_subarray_a96e1fef17ed23cb: (arg0, arg1, arg2) => arg0.subarray(arg1 >>> 0, arg2 >>> 0),
  __wbg_versions_4e31226f5e8dc909: (arg0) => arg0.versions,
  __wbindgen_cast_0000000000000001: (arg0, arg1) => getArrayU8FromWasm(arg0, arg1),
  __wbindgen_cast_0000000000000002: (arg0, arg1) => getStringFromWasm(arg0, arg1),
  __wbindgen_init_externref_table: () => {
    const table = wasm['__wbindgen_externrefs'];
    const offset = table.grow(4);
    table.set(0, undefined);
    table.set(offset + 0, undefined);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
  },
};

const imports = {
  './pezkuwi_wasm_crypto_bg.js': import0,
};

console.log('\nInstantiating WASM...');

try {
  const result = await WebAssembly.instantiate(wasmBytes, imports);
  wasm = result.instance.exports;

  console.log('WASM initialized!');

  // Initialize
  if (wasm['__wbindgen_start']) {
    wasm['__wbindgen_start']();
    console.log('Called __wbindgen_start');
  }

  // Test get_signing_context
  console.log('\n--- Testing get_signing_context ---');
  const ret = wasm['get_signing_context']();
  const signingContext = getStringFromWasm(ret[0], ret[1]);
  wasm['__wbindgen_free'](ret[0], ret[1], 1);
  console.log('Signing context:', signingContext);

  if (signingContext === 'bizinikiwi') {
    console.log('BIZINIKIWI CONTEXT CONFIRMED!');
  } else {
    console.log('WARNING: Expected "bizinikiwi" but got:', signingContext);
    process.exit(1);
  }

  // Test sr25519_keypair_from_seed
  console.log('\n--- Testing sr25519_keypair_from_seed ---');
  const seed = new Uint8Array([
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
  ]);

  const ptr0 = passArray8ToWasm(seed, wasm['__wbindgen_malloc']);
  const len0 = WASM_VECTOR_LEN;
  const kpRet = wasm['sr25519_keypair_from_seed'](ptr0, len0);

  if (kpRet[3]) {
    console.log('ERROR: keypair generation failed');
    console.log(takeFromExternrefTable(kpRet[2]));
    process.exit(1);
  }

  const keypair = getArrayU8FromWasm(kpRet[0], kpRet[1]).slice();
  wasm['__wbindgen_free'](kpRet[0], kpRet[1] * 1, 1);

  const secretKey = keypair.slice(0, 64);
  const publicKey = keypair.slice(64, 96);

  console.log('Keypair length:', keypair.length);
  console.log('Public key:', Buffer.from(publicKey).toString('hex'));

  // Test sr25519_sign
  console.log('\n--- Testing sr25519_sign ---');
  const message = new TextEncoder().encode('test message');

  const ptr1 = passArray8ToWasm(publicKey, wasm['__wbindgen_malloc']);
  const len1 = WASM_VECTOR_LEN;
  const ptr2 = passArray8ToWasm(secretKey, wasm['__wbindgen_malloc']);
  const len2 = WASM_VECTOR_LEN;
  const ptr3 = passArray8ToWasm(message, wasm['__wbindgen_malloc']);
  const len3 = WASM_VECTOR_LEN;

  const sigRet = wasm['sr25519_sign'](ptr1, len1, ptr2, len2, ptr3, len3);

  if (sigRet[3]) {
    console.log('ERROR: signing failed');
    console.log(takeFromExternrefTable(sigRet[2]));
    process.exit(1);
  }

  const signature = getArrayU8FromWasm(sigRet[0], sigRet[1]).slice();
  wasm['__wbindgen_free'](sigRet[0], sigRet[1] * 1, 1);

  console.log('Signature:', Buffer.from(signature).toString('hex').slice(0, 64) + '...');
  console.log('Signature length:', signature.length);

  // Test sr25519_verify
  console.log('\n--- Testing sr25519_verify ---');
  const vPtr0 = passArray8ToWasm(signature, wasm['__wbindgen_malloc']);
  const vLen0 = WASM_VECTOR_LEN;
  const vPtr1 = passArray8ToWasm(message, wasm['__wbindgen_malloc']);
  const vLen1 = WASM_VECTOR_LEN;
  const vPtr2 = passArray8ToWasm(publicKey, wasm['__wbindgen_malloc']);
  const vLen2 = WASM_VECTOR_LEN;

  const verified = wasm['sr25519_verify'](vPtr0, vLen0, vPtr1, vLen1, vPtr2, vLen2);
  console.log('Verification result:', verified !== 0 ? 'SUCCESS' : 'FAILED');

  if (verified !== 0) {
    console.log('\n=========================================');
    console.log('BIZINIKIWI WASM BYTES.JS VERIFIED!');
    console.log('The npm package contains correct WASM');
    console.log('=========================================');
  } else {
    process.exit(1);
  }

} catch (error) {
  console.error('Error:', error.message);
  console.error(error.stack);
  process.exit(1);
}
