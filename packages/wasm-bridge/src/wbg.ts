// Copyright 2019-2025 @pezkuwi/wasm-bridge authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { BridgeBase, WasmBaseInstance } from './types.js';

import { getRandomValues } from '@pezkuwi/x-randomvalues';

const DEFAULT_CRYPTO = { getRandomValues };
const DEFAULT_SELF = { crypto: DEFAULT_CRYPTO };

/**
 * @name Wbg
 * @description
 * This defines the internal interfaces that wasm-bindgen used to communicate
 * with the host layer. None of these functions are available to the user, rather
 * they are called internally from the WASM code itself.
 *
 * The interfaces here are exposed in the imports on the created WASM interfaces.
 *
 * Internally the implementation does a thin layer into the supplied bridge.
 */
export class Wbg<C extends WasmBaseInstance> {
  readonly #bridge: BridgeBase<C>;

  constructor (bridge: BridgeBase<C>) {
    this.#bridge = bridge;
  }

  /** @internal */
  abort = (): never => {
    throw new Error('abort');
  };

  /** @internal - new hash */
  __wbg___wbindgen_is_undefined_9e4d92534c42d778 = (idx: number): boolean => {
    return this.#bridge.getObject(idx) === undefined;
  };

  /** @internal - old hash for compatibility */
  __wbindgen_is_undefined = (idx: number): boolean => {
    return this.#bridge.getObject(idx) === undefined;
  };

  /** @internal - new hash */
  __wbg___wbindgen_throw_be289d5034ed271b = (ptr: number, len: number): never => {
    throw new Error(this.#bridge.getString(ptr, len));
  };

  /** @internal - old hash for compatibility */
  __wbindgen_throw = (ptr: number, len: number): never => {
    throw new Error(this.#bridge.getString(ptr, len));
  };

  /** @internal - new hash */
  __wbg_self_25aabeb5a7b41685 = (): number => {
    return this.#bridge.addObject(DEFAULT_SELF);
  };

  /** @internal - old hash for compatibility */
  __wbg_self_1b7a39e3a92c949c = (): number => {
    return this.#bridge.addObject(DEFAULT_SELF);
  };

  /** @internal - new hash */
  __wbg_require_0d6aeaec3c042c88 = (ptr: number, len: number, _extra: number): never => {
    throw new Error(`Unable to require ${this.#bridge.getString(ptr, len)}`);
  };

  /** @internal - old hash for compatibility */
  __wbg_require_604837428532a733 = (ptr: number, len: number): never => {
    throw new Error(`Unable to require ${this.#bridge.getString(ptr, len)}`);
  };

  /** @internal - new hash */
  __wbg_crypto_038798f665f985e2 = (_idx: number): number => {
    return this.#bridge.addObject(DEFAULT_CRYPTO);
  };

  /** @internal - old hash for compatibility */
  __wbg_crypto_968f1772287e2df0 = (_idx: number): number => {
    return this.#bridge.addObject(DEFAULT_CRYPTO);
  };

  /** @internal - new hash */
  __wbg_msCrypto_ff35fce085fab2a3 = (_idx: number): number => {
    // msCrypto for IE11, return undefined/null
    return this.#bridge.addObject(undefined);
  };

  /** @internal - new hash */
  __wbg_getRandomValues_7dfe5bd1b67c9ca1 = (_idx: number): number => {
    return this.#bridge.addObject(DEFAULT_CRYPTO.getRandomValues);
  };

  /** @internal - old hash for compatibility */
  __wbg_getRandomValues_a3d34b4fee3c2869 = (_idx: number): number => {
    return this.#bridge.addObject(DEFAULT_CRYPTO.getRandomValues);
  };

  /** @internal - new hash */
  __wbg_getRandomValues_371e7ade8bd92088 = (_arg0: number, ptr: number, len: number): void => {
    DEFAULT_CRYPTO.getRandomValues(this.#bridge.getU8a(ptr, len));
  };

  /** @internal - old hash for compatibility */
  __wbg_getRandomValues_f5e14ab7ac8e995d = (_arg0: number, ptr: number, len: number): void => {
    DEFAULT_CRYPTO.getRandomValues(this.#bridge.getU8a(ptr, len));
  };

  /** @internal - new hash */
  __wbg_randomFillSync_994ac6d9ade7a695 = (_idx: number, _ptr: number, _len: number): never => {
    throw new Error('randomFillSync is not available');
  };

  /** @internal - old hash for compatibility */
  __wbg_randomFillSync_d5bd2d655fdf256a = (_idx: number, _ptr: number, _len: number): never => {
    throw new Error('randomFillSync is not available');
  };

  /** @internal */
  __wbindgen_object_drop_ref = (idx: number): void => {
    this.#bridge.takeObject(idx);
  };

  /** @internal - new: static accessor for MODULE */
  __wbg_static_accessor_MODULE_ef3aa2eb251158a5 = (): number => {
    return this.#bridge.addObject(undefined);
  };

  /** @internal - new: Uint8Array.new_with_length */
  __wbg_new_with_length_a2c39cbe88fd8ff1 = (len: number): number => {
    return this.#bridge.addObject(new Uint8Array(len));
  };

  /** @internal - new: Uint8Array.subarray */
  __wbg_subarray_a96e1fef17ed23cb = (idx: number, start: number, end: number): number => {
    const arr = this.#bridge.getObject(idx) as Uint8Array;
    return this.#bridge.addObject(arr.subarray(start, end));
  };

  /** @internal - new: Uint8Array.length */
  __wbg_length_32ed9a279acd054c = (idx: number): number => {
    const arr = this.#bridge.getObject(idx) as Uint8Array;
    return arr.length;
  };

  /** @internal - new: Uint8Array.prototype.set.call */
  __wbg_prototypesetcall_bdcdcc5842e4d77d = (destIdx: number, srcIdx: number, offset: number): void => {
    const dest = this.#bridge.getObject(destIdx) as Uint8Array;
    const src = this.#bridge.getObject(srcIdx) as Uint8Array;
    dest.set(src, offset);
  };

  /** @internal - new: init externref table */
  __wbindgen_init_externref_table = (): void => {
    // No-op, externref table is initialized by the runtime
  };
}
