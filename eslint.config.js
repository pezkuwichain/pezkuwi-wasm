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
      // compiled from index.ts; there is nothing here to lint
      'packages/scure-sr25519/lib/**',
      // upstream @scure/sr25519 source, kept in its own style; see the package README
      'packages/scure-sr25519/index.ts'
    ]
  }
];
