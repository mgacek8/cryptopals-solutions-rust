use crate::set1::challenge7;
use crate::set1::helpers;

use lazy_static::lazy_static;
use openssl::symm::{encrypt, Cipher};

fn encrypt_aes_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    lazy_static! {
        static ref CIPHER: Cipher = Cipher::aes_128_ecb();
    }

    let encrypted = encrypt(*CIPHER, key, None, data)?;
    Ok(encrypted)
}

// Doesnt work: panics. ERROR:
// thread 'set2::challenge10::tests::can_decrypt_aes_cbc' panicked at 'called `Result::unwrap()` on an `Err` value: ErrorStack([Error { code: 101077092, library: "digital envelope routines", function: "EVP_DecryptFinal_ex", reason: "bad decrypt", file: "crypto\\evp\\evp_enc.c", line: 583 }])', src\set2\challenge10.rs:25:71
pub fn decrypt_aes_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let mut cipher_text_to_xor = iv.to_vec();
    let mut plain_bytes = vec![];
    for chunk in data.chunks(block_size) {
        let half_decrypted = challenge7::decrypt_aes_ecb(&chunk, key).unwrap();
        let decrypted = helpers::fixed_xor_bytes(&half_decrypted, &cipher_text_to_xor);
 

        cipher_text_to_xor = chunk.to_vec();
        plain_bytes.extend_from_slice(&decrypted);
    }

    plain_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1::helpers;

    #[test]
    fn can_encrypt_aes_ecb() {
        let plain_text = b"Test text with some random text in it.";
        let key = b"YELLOW SUBMARINE";

        let cipher_text = encrypt_aes_ecb(plain_text, key).unwrap();
        let decrypted = challenge7::decrypt_aes_ecb(&cipher_text, key).unwrap();
        assert_eq!(plain_text.to_vec(), decrypted);
        assert_ne!(cipher_text.to_vec(), decrypted);
    }

    #[test]
    fn can_decrypt_aes_cbc() {
        let key = b"YELLOW SUBMARINE";
        let iv = [0; 128];
        let data = helpers::read_and_decode_from_file("data/10.txt").unwrap();

        let plain_bytes = decrypt_aes_cbc(&data, key, &iv.to_vec());
        println!(
            "plain text: {}",
            std::str::from_utf8(&plain_bytes).unwrap().to_string()
        );
    }
}
