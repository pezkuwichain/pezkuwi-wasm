// Copyright 2019-2025 @pezkuwi/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

// Randomness comes from the host: the bridge fills the buffer with
// getRandomValues from @pezkuwi/x-randomvalues. It is one import with a fixed
// name, so the bridge does not have to track the hashed names wasm-bindgen
// gives the getrandom "js" backend.
#[cfg(target_arch = "wasm32")]
mod random {
	#[link(wasm_import_module = "wbg")]
	extern "C" {
		fn ext_fill_random(ptr: *mut u8, len: usize);
	}

	fn fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
		// getRandomValues fills at most 65536 bytes per call
		for chunk in buf.chunks_mut(65536) {
			unsafe { ext_fill_random(chunk.as_mut_ptr(), chunk.len()) };
		}

		Ok(())
	}

	getrandom::register_custom_getrandom!(fill);
}

#[path = "rs/bip39.rs"]
pub mod bip39;

#[path = "rs/ed25519.rs"]
pub mod ed25519;

#[path = "rs/hashing.rs"]
pub mod hashing;

#[path = "rs/secp256k1.rs"]
pub mod secp256k1;

#[path = "rs/sr25519.rs"]
pub mod sr25519;

#[path = "rs/vrf.rs"]
pub mod vrf;

#[path = "rs/kat.rs"]
pub mod kat;
