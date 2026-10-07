// Copyright 2017-2026 @pezkuwi/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

import baseConfig from '@pezkuwi/dev/config/eslint';

export default [
  ...baseConfig,
  {
    ignores: [
      'mod.ts',
      '**/bytes.js',
      '**/build/**',
      '**/build-*/**',
      // compiled sources only; there is nothing here to lint
      'packages/scure-sr25519/lib/**'
    ]
  }
];
