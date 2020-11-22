extern crate base64;

pub fn hex_to_base64(hex: &str) -> String {
    let bytes_from_hex = hex_to_bytes(hex);
    base64::encode(&bytes_from_hex)
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|byte| std::str::from_utf8(byte).unwrap())
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_convert_hex_to_base64() {
        let hex_as_str =
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        let base64_as_str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(hex_to_base64(hex_as_str), base64_as_str);
    }
}
