use super::challenge1;
use super::challenge3;

#[allow(dead_code)]
pub fn detect_single_character_xor() -> String {
    let content = std::fs::read_to_string("data/4.txt").unwrap();

    let mut score = 0;
    let mut deciphered = "".to_string();
    for line in content.split("\n") {
        let result =
            challenge3::detect_single_byte_xor_cipher(challenge1::hex_to_bytes(line).as_slice());
        if score < result.score {
            score = result.score;
            deciphered = result.result_string;
        }
    }

    deciphered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_detect_single_character_xor() {
        assert_eq!(
            detect_single_character_xor(),
            "Now that the party is jumping\n"
        )
    }
}
