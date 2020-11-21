#[allow(dead_code)]
pub struct SingleByteXorResult {
    pub key: u8,
    pub result_string: String,
    pub score: usize,
}

#[allow(dead_code)]
pub fn detect_single_byte_xor_cipher(decrypted: &[u8]) -> SingleByteXorResult {
    fn calc_score(s: &str) -> usize {
          s
            .chars()
            .filter(|&x| x.is_ascii_alphabetic() || x == ' ')
            .count()
    }

    let mut max_score = 0;
    let mut max_score_byte = 0u8;
    let mut max_score_result = String::new();
    for key in 0..255 {
        let result_vec: Vec<u8> = decrypted.iter().map(|a| key ^ *a).collect();

        let result = match std::str::from_utf8(result_vec.as_slice()) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let score = calc_score(result);
        if score > max_score {
            max_score = score;
            max_score_byte = key;
            max_score_result = result.to_string();
        }
    }

    SingleByteXorResult {
        key: max_score_byte,
        score: max_score,
        result_string: max_score_result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set1::challenge1;

    #[test]
    fn can_detect_single_byte_xor_cipher() {
        let hex_encoded = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let bytes = challenge1::hex_to_bytes(hex_encoded);
        let result = detect_single_byte_xor_cipher(bytes.as_slice());

        assert_eq!(result.result_string, "Cooking MC's like a pound of bacon");
        assert_eq!(result.key, b'X');
        assert_eq!(result.score, 33);
    }
}
