// Copyright 2019-2026 @pezkuwi/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

import { createBundle } from '@pezkuwi/dev/config/rollup';

const pkgs = [
  '@pezkuwi/wasm-crypto'
];

const external = [
  ...pkgs,
  '@pezkuwi/util'
];

const overrides = pkgs
  .map((n) => n.replace('@pezkuwi/wasm-', ''))
  .reduce((map, n) => ({
    ...map,
    [`@pezkuwi/wasm-${n}`]: {
      entries: [
        'bridge',
        'util',
        ...['init', 'asmjs', 'wasm'].map((p) => `${n}-${p}`)
      ].reduce((all, p) => ({
        ...all,
        [`@pezkuwi/wasm-${p}`]: `../../wasm-${p}/build/bundle.js`
      }), {})
    }
  }), {});

export default pkgs.map((pkg) =>
  createBundle({
    external,
    pkg,
    ...(overrides[pkg] || {})
  })
);
