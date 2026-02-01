// Copyright 2019-2026 @pezkuwi/wasm-crypto-init authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { InitFn } from '@pezkuwi/wasm-bridge/types';
import type { WasmCryptoInstance } from './types.js';

import { createWasmFn } from '@pezkuwi/wasm-bridge';
import { wasmBytes } from '@pezkuwi/wasm-crypto-wasm';

export { packageInfo } from './packageInfo.js';

/**
 * @name createWasm
 * @description
 * Creates an interface using only WASM
 */
export const createWasm: InitFn<WasmCryptoInstance> = /*#__PURE__*/ createWasmFn('crypto', wasmBytes, null);
