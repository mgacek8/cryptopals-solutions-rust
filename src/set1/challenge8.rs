use std::fs::File;
use std::io::{prelude::*, BufReader};

pub fn detect_ecb_aes(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    const AES_BLOCK_SIZE_IN_BYTES: usize = 16;

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    let mut max = 0;
    let mut result_line = String::new();
    for line in reader.lines() {
        let line = line?;
        let decoded = hex::decode(line.as_bytes())?;

        let mut score = 0;
        // Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
        let mut chunks_to_check: Vec<&[u8]> = decoded.chunks(AES_BLOCK_SIZE_IN_BYTES).collect();
        for chunk in decoded.chunks(AES_BLOCK_SIZE_IN_BYTES) {
            // No more elements to check
            if chunks_to_check.is_empty() {
                break;
            }
            let len_before = chunks_to_check.len();
            chunks_to_check.retain(|&x| x != chunk);

            let deleted_elems_len = len_before - chunks_to_check.len();
            // If a chunk is not similar to others, then we will only delete itself.
            if deleted_elems_len > 1 {
                score += deleted_elems_len;
            }
        }
        if max < score {
            max = score;
            result_line = line;
        }
    }

    Ok(result_line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_detect_ecb_aes() {
        let result = detect_ecb_aes("data/8.txt").unwrap();
        let expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";

        assert_eq!(result, expected);
    }
}
