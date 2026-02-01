// Copyright 2019-2026 @pezkuwi/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

import '@pezkuwi/wasm-crypto/initOnlyAsm';

import * as wasm from '@pezkuwi/wasm-crypto';

import { runUnassisted } from './all/index.js';

runUnassisted('ASM', wasm);
