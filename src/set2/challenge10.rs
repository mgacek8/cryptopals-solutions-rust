use crate::set1::helpers;
use crate::set2::challenge09;

use lazy_static::lazy_static;
use openssl::symm::{encrypt, Cipher, Crypter, Mode};

fn encrypt_aes_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    lazy_static! {
        static ref CIPHER: Cipher = Cipher::aes_128_ecb();
    }

    let encrypted = encrypt(*CIPHER, key, None, data)?;
    Ok(encrypted)
}

pub fn decrypt_aes_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let mut cipher_text_to_xor = iv.to_vec();
    let mut plain_bytes = vec![];
    for chunk in data.chunks(block_size) {
        let half_decrypted = decrypt_aes_ecb_no_padding(&chunk, key);
        let decrypted = helpers::fixed_xor_bytes(&half_decrypted, &cipher_text_to_xor);
        plain_bytes.extend_from_slice(&decrypted);
        cipher_text_to_xor = chunk.to_vec();
    }

    challenge09::pkcs_7_unpad(&plain_bytes)
}

pub fn decrypt_aes_ecb_no_padding(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None).unwrap();

    let block_size = Cipher::aes_128_cbc().block_size();
    decrypter.pad(false);

    let mut plaintext = vec![0; data.len() + block_size];
    let count = decrypter.update(data, &mut plaintext).unwrap();
    plaintext.truncate(count);

    plaintext
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
    fn can_encrypt_aes_cbc_no_padding() {
        let key = b"YELLOW SUBMARINE";
        let iv = [0; 128];
        let data = helpers::read_and_decode_from_file("data/10.txt").unwrap();

        let plain_bytes = decrypt_aes_cbc(&data, key, &iv.to_vec());
        let result = std::str::from_utf8(&plain_bytes).unwrap().to_string();
        let expected = std::fs::read_to_string("data/vanilla_ice.txt").unwrap();

        assert_eq!(expected, result);
    }
}
