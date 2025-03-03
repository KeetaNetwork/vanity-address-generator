use rand_core::RngCore as _;
use sha3::Digest as _;
use gumdrop::Options as _;

fn bytes_to_hex(bytes: &[u8]) -> String {
	let hex_str = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
	return hex_str;
}

fn seed_from_passphrase(passphrase: &str) -> Result<[u8; 32], String> {
	let min_passphrase_length = 60;
	let clean_passphrase = passphrase.to_lowercase().replace(" ", "");
	let clean_passphrase_buffer = clean_passphrase.as_bytes();
	if clean_passphrase_buffer.len() < min_passphrase_length {
		return Err(format!("Invalid passphrase, must be at least {} bytes after internal processing, got {}", min_passphrase_length, clean_passphrase_buffer.len()));
	}

	let mut key = [0u8; 32];
	pbkdf2::pbkdf2_hmac::<sha2::Sha256>(clean_passphrase_buffer, clean_passphrase_buffer, 64000, &mut key);

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
		return Err(format!("internal error: Got incorrect length for public key: {} !== 38 or 39", pub_key_values.len()));
	}

	let pub_key_formatted = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &pub_key_values);

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

fn main() -> Result<(), i32> {
	let opts = CLIOptions::parse_args_default_or_exit();
	if opts.args.len() != 1 {
		eprintln!("Invalid number of arguments -- must supply a search string");
		eprintln!("{}", CLIOptions::usage());
		return Err(1);
	}

	let max_index: u32 = opts.max_index.unwrap_or(u32::MAX - 1);
	let default_thread_count = (num_cpus::get() as f64 / 2.0 + 0.6).trunc() as usize;
	let thread_count: usize = opts.thread_count.unwrap_or(default_thread_count);
	let use_passphrase = opts.use_passphrase;

	let search_basic = opts.args[0].clone();
	let search_start_offset: usize = 9;

	let check = base32::decode(base32::Alphabet::Rfc4648Lower { padding: false }, search_basic.as_str());
	if check.is_none() {
		eprintln!("Invalid search string -- must be a valid RFC4648 base32 string");
		return Err(1);
	}

	println!("Searching for public key starting or ending with {} with {} threads", search_basic, thread_count);

	let found = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let checks_performed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
	std::thread::scope(|s| {
		for _ in 0..thread_count {
			let thread_search_start = search_basic.clone();
			let thread_search_end = search_basic.clone();
			let thread_found = found.clone();
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

							thread_found.store(true, std::sync::atomic::Ordering::Relaxed);

							if passphrase.is_some() {
								println!("Passphrase : {}", passphrase.unwrap());
							}
							println!("Seed       : {}", bytes_to_hex(&seed));
							println!("Index      : {}", index);
							println!("Secret Key : {}", key.display_secret());
							println!("Public Key : {}", public_key_string);
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
