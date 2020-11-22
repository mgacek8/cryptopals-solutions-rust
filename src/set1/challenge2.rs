use super::challenge1;

/// Takes two equal-length buffers and produces their XOR combination.
pub fn fixed_xor(s1: &str, s2: &str) -> String {
    let s1_bytes = challenge1::hex_to_bytes(s1);
    let s2_bytes = challenge1::hex_to_bytes(s2);

    let result: Vec<u8> = s1_bytes
        .iter()
        .zip(s2_bytes.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_perform_fixed_xor() {
        assert_eq!(
            fixed_xor(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            ),
            "746865206b696420646f6e277420706c6179"
        );
    }
}
