use crate::set1::helpers;
use crate::set2::challenge09;

use lazy_static::lazy_static;
use openssl::symm::{encrypt, Cipher, Crypter, Mode};

pub fn encrypt_aes_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    lazy_static! {
        static ref CIPHER: Cipher = Cipher::aes_128_ecb();
    }

    let encrypted = encrypt(*CIPHER, key, None, data)?;
    Ok(encrypted)
}

pub fn decrypt_aes_cbc(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let block_size = 16;
    let mut next_iv = iv.to_vec();
    let mut plain_bytes = vec![];
    for chunk in data.chunks(block_size) {
        let half_decrypted = aes_ecb_no_padding(Mode::Decrypt, &chunk, key)?;
        let decrypted = helpers::fixed_xor_bytes(&half_decrypted, &next_iv);
        plain_bytes.extend_from_slice(&decrypted);
        next_iv = chunk.to_vec();
    }

    Ok(challenge09::pkcs_7_unpad(&plain_bytes))
}

pub fn encrypt_aes_cbc(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let block_size = 16;
    let padded = challenge09::pkcs_7(&data, block_size);
    let mut next_iv = iv.to_vec();
    let mut cipher_text = vec![];
    for chunk in padded.chunks(block_size) {
        let xored = helpers::fixed_xor_bytes(&chunk, &next_iv);
        let encrypted_chunk = aes_ecb_no_padding(Mode::Encrypt, &xored, key)?;
        cipher_text.extend_from_slice(&encrypted_chunk);
        next_iv = encrypted_chunk;
    }

    Ok(cipher_text)
}

pub fn aes_ecb_no_padding(
    mode: Mode,
    data: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    lazy_static! {
        static ref CIPHER: Cipher = Cipher::aes_128_ecb();
    }
    let mut crypter = Crypter::new(*CIPHER, mode, key, None)?;

    crypter.pad(false);

    let mut result = vec![0; data.len() + CIPHER.block_size()];
    let count = crypter.update(data, &mut result)?;
    result.truncate(count);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1::challenge7;
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

        let plain_bytes = decrypt_aes_cbc(&data, key, &iv).unwrap();
        let result = std::str::from_utf8(&plain_bytes).unwrap().to_string();
        let expected = std::fs::read_to_string("data/vanilla_ice.txt").unwrap();

        assert_eq!(expected, result);
    }

    // parametrized tests with https://crates.io/crates/rstest
    #[test]
    fn can_encrypt_and_decrypt_aes_cbc() {
        // let plain_text = b"Test with ";
        let plain_text = b"Test with some i";
        let key = b"YELLOW SUBMARINE";
        let iv = [0; 128];

        let cipher_text = encrypt_aes_cbc(plain_text, key, &iv).unwrap();
        let decrypted = decrypt_aes_cbc(&cipher_text, key, &iv).unwrap();

        assert_eq!(plain_text.to_vec(), decrypted);
        assert_ne!(cipher_text.to_vec(), decrypted);
    }
}
