use lazy_static::lazy_static;
use openssl::symm::Cipher;

pub fn decrypt_aes_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    lazy_static! {
        static ref CIPHER: Cipher = Cipher::aes_128_ecb();
    }
    let decrypt = openssl::symm::decrypt(*CIPHER, key, None, &data)?;
    Ok(decrypt)
}


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::helpers;

    #[test]
    fn can_decrypt_aes_ecb() {
        let key = b"YELLOW SUBMARINE";
        let result = decrypt_aes_ecb(&helpers::read_and_decode_from_file("data/7.txt").unwrap(), key).unwrap();
        let result = std::str::from_utf8(&result).unwrap();

        let expected = std::fs::read_to_string("data/vanilla_ice.txt").unwrap();
        assert_eq!(&expected, result);
    }
}
