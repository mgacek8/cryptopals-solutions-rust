pub fn read_and_decode_from_file(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)?;
    let data: String = data.split('\n').collect();
    Ok(base64::decode(data)?)
}

pub fn fixed_xor_bytes(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    let result: Vec<u8> = lhs.iter().zip(rhs.iter()).map(|(a, b)| a ^ b).collect();

    result
}
