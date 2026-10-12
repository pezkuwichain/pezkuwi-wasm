// Copyright 2019-2025 @pezkuwi/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

//! Known-answer vectors for every exported function.
//!
//! `kat.txt` was produced by an earlier build and is checked in. Any change to
//! the crypto crates must leave every deterministic output byte-equal, and the
//! randomised signatures (sr25519, VRF proofs) recorded there must still
//! verify. Regenerate only on purpose:
//!
//!   KAT_WRITE=src/rs/kat.txt cargo test --release kat_ -- --nocapture

#[cfg(test)]
pub mod tests {
	use crate::bip39::*;
	use crate::ed25519::*;
	use crate::hashing::*;
	use crate::secp256k1::*;
	use crate::sr25519::*;
	use crate::vrf::*;

	const VECTORS: &str = include_str!("kat.txt");

	const PHRASES: [&str; 3] = [
		"bottom drive obey lake curtain smoke basket hold race lonely fit walk",
		"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
	];

	fn to_hex(data: &[u8]) -> String {
		data.iter().map(|b| format!("{:02x}", b)).collect()
	}

	fn from_hex(s: &str) -> Vec<u8> {
		(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
	}

	fn pattern(len: usize, mul: usize) -> Vec<u8> {
		(0..len).map(|i| ((i * mul + 7) % 251) as u8).collect()
	}

	fn datas() -> Vec<Vec<u8>> {
		vec![vec![], b"abc".to_vec(), pattern(1000, 31)]
	}

	fn seeds() -> Vec<Vec<u8>> {
		vec![vec![0u8; 32], pattern(32, 1), pattern(32, 97), b"12345678901234567890123456789012".to_vec()]
	}

	fn chain_codes() -> Vec<Vec<u8>> {
		// "Alice" as a SCALE-encoded string, zero padded, as util-crypto builds it
		let mut alice = vec![0u8; 32];

		alice[0] = 5 << 2;
		alice[1..6].copy_from_slice(b"Alice");

		vec![alice, pattern(32, 13)]
	}

	fn messages() -> Vec<Vec<u8>> {
		vec![vec![], b"this is a message".to_vec(), pattern(300, 7)]
	}

	/// Every deterministic output, as `name hex` lines.
	fn deterministic() -> Vec<(String, Vec<u8>)> {
		let mut out: Vec<(String, Vec<u8>)> = Vec::new();

		for (d, data) in datas().iter().enumerate() {
			for size in [32u32, 64] {
				out.push((format!("blake2b/{}/{}", d, size), ext_blake2b(data, &[], size)));
				out.push((format!("blake2b-key/{}/{}", d, size), ext_blake2b(data, b"key", size)));
			}

			out.push((format!("keccak256/{}", d), ext_keccak256(data)));
			out.push((format!("keccak512/{}", d), ext_keccak512(data)));
			out.push((format!("sha256/{}", d), ext_sha256(data)));
			out.push((format!("sha512/{}", d), ext_sha512(data)));
			out.push((format!("hmac256/{}", d), ext_hmac_sha256(b"key", data)));
			out.push((format!("hmac512/{}", d), ext_hmac_sha512(b"key", data)));

			for rounds in [1u32, 2, 4] {
				out.push((format!("twox/{}/{}", d, rounds), ext_twox(data, rounds)));
			}

			for rounds in [1u32, 2048] {
				out.push((format!("pbkdf2/{}/{}", d, rounds), ext_pbkdf2(data, b"salt", rounds)));
			}

			out.push((format!("scrypt/{}", d), ext_scrypt(data, b"salt", 10, 8, 1)));
		}

		for (p, phrase) in PHRASES.iter().enumerate() {
			out.push((format!("bip39-valid/{}", p), vec![ext_bip39_validate(phrase) as u8]));
			out.push((format!("bip39-entropy/{}", p), ext_bip39_to_entropy(phrase)));

			for (w, password) in ["", "password"].iter().enumerate() {
				out.push((format!("bip39-mini/{}/{}", p, w), ext_bip39_to_mini_secret(phrase, password)));
				out.push((format!("bip39-seed/{}/{}", p, w), ext_bip39_to_seed(phrase, password)));
			}
		}

		out.push(("bip39-valid/bad-checksum".into(), vec![ext_bip39_validate(&PHRASES[1].replace("about", "abandon")) as u8]));

		let pairs: Vec<Vec<u8>> = seeds().iter().map(|s| ext_sr_from_seed(s)).collect();

		for (s, pair) in pairs.iter().enumerate() {
			out.push((format!("sr-from-seed/{}", s), pair.clone()));

			for (c, cc) in chain_codes().iter().enumerate() {
				let soft = ext_sr_derive_keypair_soft(pair, cc);

				out.push((format!("sr-derive-hard/{}/{}", s, c), ext_sr_derive_keypair_hard(pair, cc)));
				// schnorrkel draws the nonce half of a soft-derived secret at random
				out.push((format!("sr-derive-soft/{}/{}", s, c), [&soft[..32], &soft[64..]].concat()));
				out.push((format!("sr-derive-public-soft/{}/{}", s, c), ext_sr_derive_public_soft(&pair[64..], cc)));

				// the public derivation must land on the public half of the soft pair
				assert_eq!(ext_sr_derive_public_soft(&pair[64..], cc), soft[64..].to_vec());
			}

			for (o, other) in pairs.iter().enumerate() {
				out.push((format!("sr-agree/{}/{}", s, o), ext_sr_agree(&other[64..], &pair[..64])));
			}

			for (m, msg) in messages().iter().enumerate() {
				// the VRF output (not the proof) is a function of key and input only
				out.push((format!("vrf-output/{}/{}", s, m), ext_vrf_sign(&pair[..64], b"ctx", msg, b"extra")[..32].to_vec()));
			}
		}

		for (s, seed) in seeds().iter().enumerate() {
			let ed = ext_ed_from_seed(seed);

			out.push((format!("ed-from-seed/{}", s), ed.clone()));

			for (m, msg) in messages().iter().enumerate() {
				out.push((format!("ed-sign/{}/{}", s, m), ext_ed_sign(&ed[32..], &ed[..32], msg)));
			}
		}

		// a zero scalar is not a secp256k1 secret key
		for (s, seed) in seeds().iter().enumerate().skip(1) {
			let secp = ext_secp_from_seed(seed);

			out.push((format!("secp-from-seed/{}", s), secp.clone()));
			out.push((format!("secp-expand/{}", s), ext_secp_pub_expand(&secp[32..])));
			out.push((format!("secp-compress/{}", s), ext_secp_pub_compress(&ext_secp_pub_expand(&secp[32..]))));

			for (m, msg) in messages().iter().enumerate() {
				let hash = ext_keccak256(msg);
				let sig = ext_secp_sign(&hash, &secp[..32]);

				out.push((format!("secp-sign/{}/{}", s, m), sig.clone()));
				out.push((format!("secp-recover/{}/{}", s, m), ext_secp_recover(&hash, &sig[..64], sig[64] as i32)));
			}
		}

		out
	}

	/// Randomised signatures: `kind pubkey msg sig` lines that any later build must verify.
	fn randomised() -> Vec<String> {
		let mut out = Vec::new();

		for seed in seeds().iter() {
			let pair = ext_sr_from_seed(seed);

			for msg in messages().iter() {
				out.push(format!("sr-sig {} {} {}", to_hex(&pair[64..]), to_hex(msg), to_hex(&ext_sr_sign(&pair[64..], &pair[..64], msg))));
				out.push(format!("vrf-sig {} {} {}", to_hex(&pair[64..]), to_hex(msg), to_hex(&ext_vrf_sign(&pair[..64], b"ctx", msg, b"extra"))));
			}
		}

		out
	}

	#[test]
	fn kat_vectors() {
		if let Ok(path) = std::env::var("KAT_WRITE") {
			let mut lines: Vec<String> = deterministic().iter().map(|(n, v)| format!("{} {}", n, to_hex(v))).collect();

			lines.extend(randomised());
			std::fs::write(&path, lines.join("\n") + "\n").unwrap();
			println!("wrote {} vectors to {}", lines.len(), path);

			return;
		}

		let mut expected = std::collections::HashMap::new();
		let mut signatures = 0;

		for line in VECTORS.lines() {
			let parts: Vec<&str> = line.split(' ').collect();

			match parts[0] {
				"sr-sig" => {
					assert!(ext_sr_verify(&from_hex(parts[3]), &from_hex(parts[2]), &from_hex(parts[1])), "{}", line);
					signatures += 1;
				},
				"vrf-sig" => {
					assert!(ext_vrf_verify(&from_hex(parts[1]), b"ctx", &from_hex(parts[2]), b"extra", &from_hex(parts[3])), "{}", line);
					signatures += 1;
				},
				name => {
					expected.insert(name.to_string(), parts[1].to_string());
				},
			}
		}

		let actual = deterministic();

		assert_eq!(actual.len(), expected.len(), "vector count");

		for (name, value) in actual.iter() {
			assert_eq!(&to_hex(value), expected.get(name).expect(name), "{}", name);
		}

		assert!(signatures > 0);
		println!("{} deterministic vectors equal, {} recorded signatures verify", actual.len(), signatures);
	}
}
