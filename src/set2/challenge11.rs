use crate::set2::challenge10;
use rand::distributions;
use rand::Rng;

// https://users.rust-lang.org/t/lazily-initialized-static-variable-with-random-number-generator/11950
// https://users.rust-lang.org/t/global-mutable-rng/16253/7
// https://rust-random.github.io/book/guide-start.html

fn generate_random_value(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

enum AesMode {
    ECB,
    CBC,
}

pub fn encryption_oracle(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Under the hood, have the function append 5-10 bytes (count chosen randomly)
    // before the plaintext and 5-10 bytes after the plaintext.
    let mut thread_rng = rand::thread_rng();
    let bytes_to_append = thread_rng.gen_range(5, 11);
    let rand_string: String = thread_rng
        .sample_iter(&distributions::Alphanumeric)
        .take(bytes_to_append)
        .collect();

    let appended_data = [rand_string.as_bytes(), data, rand_string.as_bytes()].concat();

    let key = generate_random_value(16);

    let aes_mode = {
        if thread_rng.gen_bool(0.5) {
            AesMode::ECB
        } else {
            AesMode::CBC
        }
    };

    match aes_mode {
        AesMode::ECB => challenge10::encrypt_aes_ecb(&appended_data, &key),
        AesMode::CBC => {
            let iv = generate_random_value(16);
            challenge10::encrypt_aes_cbc(&appended_data, &key, &iv)
        }
    }
}
