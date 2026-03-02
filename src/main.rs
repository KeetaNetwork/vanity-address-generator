use gumdrop::Options as _;
use rand_core::RngCore as _;
use sha3::Digest as _;

fn bytes_to_hex(bytes: &[u8]) -> String {
	let hex_str = bytes
		.iter()
		.map(|b| format!("{:02x}", b))
		.collect::<String>();
	return hex_str;
}

fn seed_from_passphrase(passphrase: &str) -> Result<[u8; 32], String> {
	let min_passphrase_length = 60;
	let clean_passphrase = passphrase.to_lowercase().replace(" ", "");
	let clean_passphrase_buffer = clean_passphrase.as_bytes();
	if clean_passphrase_buffer.len() < min_passphrase_length {
		return Err(format!(
			"Invalid passphrase, must be at least {} bytes after internal processing, got {}",
			min_passphrase_length,
			clean_passphrase_buffer.len()
		));
	}

	let mut key = [0u8; 32];
	pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
		clean_passphrase_buffer,
		clean_passphrase_buffer,
		64000,
		&mut key,
	);

	return Ok(key);
}

fn combine_seed_and_index(seed: &[u8], index: u32) -> [u8; 36] {
	let mut indexed_seed = [0u8; 36];
	indexed_seed[..32].copy_from_slice(seed);
	indexed_seed[32] = (index >> 24) as u8;
	indexed_seed[33] = (index >> 16) as u8;
	indexed_seed[34] = (index >> 8) as u8;
	indexed_seed[35] = index as u8;

	return indexed_seed;
}

fn seed_to_private_key(seed: &[u8], index: u32) -> Result<secp256k1::SecretKey, secp256k1::Error> {
	let seed_buffer = combine_seed_and_index(seed, index);

	let hkdf_object = hkdf::Hkdf::<sha3::Sha3_256>::from_prk(&seed_buffer);
	let mut key = [0u8; 32];

	if hkdf_object.is_err() {
		return Err(secp256k1::Error::InvalidSecretKey);
	}

	let can_key = hkdf_object.unwrap().expand(&[0u8; 0], &mut key);
	if can_key.is_err() {
		return Err(secp256k1::Error::InvalidSecretKey);
	}

	return secp256k1::SecretKey::from_byte_array(&key);
}

fn derive_public_key_string(key: &secp256k1::SecretKey) -> Result<String, String> {
	let secp = secp256k1::Secp256k1::signing_only();
	let public_key = key.public_key(&secp);
	let serialized = public_key.serialize();
	let mut pub_key_values = vec![0u8; 1];
	pub_key_values.extend_from_slice(&serialized);

	let checksum_of = Vec::from(&pub_key_values[..]);
	let mut hasher = sha3::Sha3_256::new();
	hasher.update(&checksum_of);
	let checksum = hasher.finalize();

	/* Copy the first 5 bytes of the checksum to the public key */
	pub_key_values.extend_from_slice(&checksum[..5]);

	if pub_key_values.len() != 38 && pub_key_values.len() != 39 {
		return Err(format!(
			"internal error: Got incorrect length for public key: {} !== 38 or 39",
			pub_key_values.len()
		));
	}

	let pub_key_formatted = base32::encode(
		base32::Alphabet::Rfc4648Lower { padding: false },
		&pub_key_values,
	);

	return Ok(format!("keeta_{}", pub_key_formatted));
}

fn generate_random_passphrase() -> String {
	let mut passphrase_buffer: String = "".to_owned();
	let words = bip39_dict::ENGLISH.words;
	let word_count = words.len() as u32;

	for i in 0..24 {
		let word_index = rand_core::OsRng.next_u32() % word_count;
		let word = words[word_index as usize];
		if i > 0 {
			passphrase_buffer.push_str(" ");
		}
		passphrase_buffer.push_str(word);
	}

	return passphrase_buffer;
}

fn generate_random_seed() -> [u8; 32] {
	let mut seed_buffer = [0u8; 32];

	rand_core::OsRng.fill_bytes(&mut seed_buffer);

	return seed_buffer;
}

#[derive(Debug, gumdrop::Options)]
struct CLIOptions {
	#[options(free, help = "text to search for")]
	args: Vec<String>,

	#[options(help = "print help message")]
	help: bool,

	#[options(help = "set number of threads", meta = "N")]
	thread_count: Option<usize>,

	#[options(help = "set maximum index", meta = "N")]
	max_index: Option<u32>,

	#[options(help = "search for passphrase (slow)")]
	use_passphrase: bool,
}

struct FoundResult {
	passphrase: Option<String>,
	seed: [u8; 32],
	index: u32,
}

fn main() -> Result<(), &'static str> {
	let opts = CLIOptions::parse_args_default_or_exit();
	if opts.args.len() != 1 {
		eprintln!("{}", CLIOptions::usage());
		return Err("Invalid number of arguments -- must supply a search string");
	}

	let max_index: u32 = opts.max_index.unwrap_or(u32::MAX - 1);
	let default_thread_count = (num_cpus::get() as f64 / 2.0 + 0.6).trunc() as usize;
	let thread_count: usize = opts.thread_count.unwrap_or(default_thread_count);
	let use_passphrase = opts.use_passphrase;

	let search_basic = opts.args[0].clone();
	let search_start_offset: usize = 9;

	let check = base32::decode(
		base32::Alphabet::Rfc4648Lower { padding: false },
		search_basic.as_str(),
	);
	if check.is_none() {
		return Err("Invalid search string -- must be a valid RFC4648 base32 string");
	}

	println!(
		"Searching for public key starting or ending with {} with {} threads",
		search_basic, thread_count
	);

	let found = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let found_result = std::sync::Arc::new(std::sync::Mutex::new(Option::<FoundResult>::None));
	let checks_performed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
	std::thread::scope(|s| {
		for _ in 0..thread_count {
			let thread_search_start = search_basic.clone();
			let thread_search_end = search_basic.clone();
			let thread_found = found.clone();
			let thread_found_result = found_result.clone();
			let thread_checks_performed = checks_performed.clone();
			s.spawn(move || {
				loop {
					let passphrase = if use_passphrase {
						Some(generate_random_passphrase())
					} else {
						None
					};

					let seed = if passphrase.is_some() {
						seed_from_passphrase(passphrase.clone().unwrap().as_str()).unwrap()
					} else {
						generate_random_seed()
					};

					for index in 0..max_index + 1 {
						if thread_found.load(std::sync::atomic::Ordering::Relaxed) {
							break;
						}

						let key = seed_to_private_key(&seed, index).unwrap();
						let public_key_string = derive_public_key_string(&key).unwrap();

						/* Skip "search_start_offset" bytes of the "public_key_string" for the search */
						let public_key_string_truncated = &public_key_string[search_start_offset..];

						/* Determine if the public key is acceptable */
						let acceptable = {
							if public_key_string_truncated.starts_with(&thread_search_start) {
								true
							} else if public_key_string_truncated.ends_with(&thread_search_end) {
								true
							} else {
								false
							}
						};

						thread_checks_performed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

						if acceptable {
							if thread_found.load(std::sync::atomic::Ordering::Relaxed) {
								break;
							}

							thread_found_result.lock().unwrap().replace(FoundResult {
								passphrase: passphrase.clone(),
								seed,
								index,
							});

							thread_found.store(true, std::sync::atomic::Ordering::Relaxed);

							break;
						}
					}

					if thread_found.load(std::sync::atomic::Ordering::Relaxed) {
						break;
					}
				}
			});
		}

		let max_estimated_checks = (2 as u64).pow(5 * search_basic.len() as u32) * 8;
		let progress_bar = indicatif::ProgressBar::new(max_estimated_checks);
		progress_bar.set_style(indicatif::ProgressStyle::with_template("[{elapsed_precise}/{eta_precise}] {wide_bar}   {human_pos}/{human_len}  {per_sec:15}").unwrap());
		loop {
			if found.load(std::sync::atomic::Ordering::Relaxed) {
				progress_bar.abandon();

				/* Ensure the result is available */
				while found_result.lock().unwrap().is_none() {
					std::thread::sleep(std::time::Duration::from_millis(100));
				}

				let result = found_result.lock().unwrap().take().unwrap();
				let key = seed_to_private_key(&result.seed, result.index).unwrap();
				let public_key_string = derive_public_key_string(&key).unwrap();

				if result.passphrase.is_some() {
					println!("Passphrase : {}", result.passphrase.unwrap());
				}
				println!("Seed       : {}", bytes_to_hex(&result.seed));
				println!("Index      : {}", result.index);
				println!("Secret Key : {}", key.display_secret());
				println!("Public Key : {}", public_key_string);
				break;
			}

			std::thread::sleep(std::time::Duration::from_millis(500));
			let checks_performed = checks_performed.load(std::sync::atomic::Ordering::Relaxed);

			progress_bar.set_position(checks_performed as u64);
			progress_bar.tick();
		}
	});

	return Ok(());
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_bytes_to_hex() {
		let bytes = vec![0x00, 0x0a, 0xff, 0x10];
		assert_eq!(bytes_to_hex(&bytes), "000aff10");
	}

	#[test]
	fn test_bytes_to_hex_empty() {
		let bytes = vec![];
		assert_eq!(bytes_to_hex(&bytes), "");
	}

	#[test]
	fn test_seed_from_passphrase_valid() {
		let passphrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
		let result = seed_from_passphrase(passphrase);
		assert!(result.is_ok());
		let seed = result.unwrap();
		assert_eq!(seed.len(), 32);
	}

	#[test]
	fn test_seed_from_passphrase_too_short() {
		let passphrase = "short";
		let result = seed_from_passphrase(passphrase);
		assert!(result.is_err());
		assert!(result.unwrap_err().contains("must be at least"));
	}

	#[test]
	fn test_seed_from_passphrase_deterministic() {
		let passphrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
		let seed1 = seed_from_passphrase(passphrase).unwrap();
		let seed2 = seed_from_passphrase(passphrase).unwrap();
		assert_eq!(seed1, seed2);
	}

	#[test]
	fn test_combine_seed_and_index() {
		let seed = [0u8; 32];
		let index = 0x12345678u32;
		let result = combine_seed_and_index(&seed, index);
		assert_eq!(result.len(), 36);
		assert_eq!(result[32], 0x12);
		assert_eq!(result[33], 0x34);
		assert_eq!(result[34], 0x56);
		assert_eq!(result[35], 0x78);
	}

	#[test]
	fn test_seed_to_private_key() {
		let seed = [1u8; 32];
		let result = seed_to_private_key(&seed, 0);
		assert!(result.is_ok());
	}

	#[test]
	fn test_derive_public_key_string() {
		let seed = [1u8; 32];
		let key = seed_to_private_key(&seed, 0).unwrap();
		let result = derive_public_key_string(&key);
		assert!(result.is_ok());
		let pub_key = result.unwrap();
		assert!(pub_key.starts_with("keeta_"));
	}

	#[test]
	fn test_generate_random_passphrase() {
		let passphrase = generate_random_passphrase();
		let words: Vec<&str> = passphrase.split(' ').collect();
		assert_eq!(words.len(), 24);
		// Verify all words are from the BIP39 dictionary
		for word in words {
			assert!(bip39_dict::ENGLISH.words.contains(&word));
		}
	}

	#[test]
	fn test_generate_random_seed() {
		let seed1 = generate_random_seed();
		let seed2 = generate_random_seed();
		assert_eq!(seed1.len(), 32);
		assert_eq!(seed2.len(), 32);
		// Seeds should be different (with very high probability)
		assert_ne!(seed1, seed2);
	}

	#[test]
	fn test_public_key_format() {
		// Test that public keys have the correct format
		let seed = [42u8; 32];
		let key = seed_to_private_key(&seed, 0).unwrap();
		let pub_key = derive_public_key_string(&key).unwrap();
		
		// Should start with "keeta_"
		assert!(pub_key.starts_with("keeta_"));
		
		// Should only contain valid base32 characters (lowercase)
		let base32_part = &pub_key[6..];
		for c in base32_part.chars() {
			assert!(c.is_ascii_lowercase() || c.is_ascii_digit());
		}
	}

	#[test]
	fn test_different_indices_produce_different_keys() {
		let seed = [5u8; 32];
		let key1 = seed_to_private_key(&seed, 0).unwrap();
		let key2 = seed_to_private_key(&seed, 1).unwrap();
		let pub1 = derive_public_key_string(&key1).unwrap();
		let pub2 = derive_public_key_string(&key2).unwrap();
		
		assert_ne!(pub1, pub2);
	}
}
