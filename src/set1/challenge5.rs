pub fn repeating_key_xor_v2(to_cipher: &[u8], key: &str) -> Vec<u8> {
    let mut key_range = (0..key.len()).cycle();
    let encripted: Vec<u8> = to_cipher
        .iter()
        .map(|byte| {
            let val = key.as_bytes()[key_range.next().unwrap()] ^ byte;
            val
        })
        .collect();

    encripted
}

pub fn repeating_key_xor(to_cipher: &[u8], key: &str) -> Vec<u8> {
    let mut encripted: Vec<u8> = vec![];

    let mut i = 0;
    for byte in to_cipher {
        encripted.push(key.as_bytes()[i] ^ byte);

        i += 1;
        if i >= key.len() {
            i = 0;
        }
    }

    encripted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_perform_repeating_key_xor() {
        let to_cipher =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let encrypted = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let key = "ICE";
        assert_eq!(
            hex::encode(repeating_key_xor(to_cipher.as_bytes(), key)),
            encrypted
        );
        assert_eq!(
            hex::encode(repeating_key_xor_v2(to_cipher.as_bytes(), key)),
            encrypted
        );
    }
}
