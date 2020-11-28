use lazy_static::lazy_static;
use openssl::symm::Cipher;

pub fn decrypt_aes_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    lazy_static! {
        static ref CIPHER: Cipher = Cipher::aes_128_ecb();
    }
    let decrypt = openssl::symm::decrypt(*CIPHER, key, None, &data)?;
    Ok(decrypt)
}

pub fn read_and_decode_from_file(path: &str) -> Vec<u8> {
    let data = std::fs::read_to_string(path).unwrap();
    let data: String = data.split("\n").collect();
    let data = base64::decode(data).unwrap();
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_decrypt_aes_ecb() {
        let key = b"YELLOW SUBMARINE";
        let result = decrypt_aes_ecb(&read_and_decode_from_file("data/7.txt"), key).unwrap();
        let result = std::str::from_utf8(&result).unwrap();

        let expected = std::fs::read_to_string("data/vanilla_ice.txt").unwrap();
        assert_eq!(&expected, result);
    }
}
