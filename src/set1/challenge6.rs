use super::challenge3;
use super::challenge5;

use std::fs::File;
use std::io::prelude::*;

const DECRYPTED_FILE_PATH: &str = "data/vanilla_ice.txt";

fn write_to_file(data: &str) -> std::io::Result<()> {
    let mut file = File::create(DECRYPTED_FILE_PATH)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

pub struct DecryptedResult {
    pub key: String,
    pub content: String,
}

pub fn break_repeating_key_xor() -> DecryptedResult {
    let content = std::fs::read_to_string("data/6.txt").unwrap();
    let content = content.split('\n');
    let content: String = content.collect();
    let ciphertext = base64::decode(content).unwrap();

    let mut min_distance = std::f32::MAX;
    let mut guessed_keysize = 0;
    for keysize in 2..41 {
        let hamming_distance = {
            let mut distance = 0;

            for step in 0..20 {
                distance += hamming_distance(
                    &ciphertext[step * keysize..(step + 1) * keysize],
                    &ciphertext[(step + 1) * keysize..(step + 2) * keysize],
                )
            }
            distance
        };

        let hamming_distance = hamming_distance as f32 / keysize as f32;
        if min_distance > hamming_distance {
            min_distance = hamming_distance;
            guessed_keysize = keysize;
        }
    }

    // Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    let blocks: Vec<&[u8]> = ciphertext.chunks(guessed_keysize).collect();

    // Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    let mut transposed = Vec::new();
    for _ in 0..guessed_keysize {
        transposed.push(vec![]);
    }

    for block in blocks {
        for idx in 0..block.len() {
            transposed[idx].push(block[idx]);
        }
    }

    // Solve each block as if it was single-character XOR
    let mut key = String::new();
    for block in transposed {
        let result = challenge3::detect_single_byte_xor_cipher(block.as_slice());
        key.push(result.key as char);
    }

    let decripted = challenge5::repeating_key_xor(ciphertext.as_slice(), &key);
    let decrypted_content = std::str::from_utf8(decripted.as_slice()).unwrap();

    DecryptedResult {
        key,
        content: decrypted_content.to_string(),
    }
}

/// The number of differing bits
pub fn hamming_distance(s1: &[u8], s2: &[u8]) -> u32 {
    s1.iter()
        .zip(s2.iter())
        .fold(0, |acc, (&a, &b)| acc + (a ^ b).count_ones())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_calculate_hamming_distance() {
        assert_eq!(
            hamming_distance(b"this is a test", b"wokka wokka!!!"),
            37
        );
    }

    #[test]
    fn can_break_repeating_key_xor() {
        let result = break_repeating_key_xor();
        // let _ = write_to_file(&result.content);
        let expected = std::fs::read_to_string(DECRYPTED_FILE_PATH).unwrap();

        assert_eq!("Terminator X: Bring the noise", result.key);
        assert_eq!(expected, result.content);
    }
}
