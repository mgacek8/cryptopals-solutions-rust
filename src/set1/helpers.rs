pub fn read_and_decode_from_file(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(path)?;
    let data: String = data.split('\n').collect();
    Ok(base64::decode(data)?)
}