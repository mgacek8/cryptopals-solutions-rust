/// Implements PKCS#7 padding.
///
/// PKCS#7 padding is defined in [RFC 5652](https://tools.ietf.org/html/rfc5652#section-6.3).
pub fn pkcs_7(data: &[u8], padding_size: usize) -> Vec<u8> {
    let bytes_to_pad = {
        let modulo = padding_size % data.len();
        if modulo == 0 {
            padding_size
        } else {
            modulo
        }
    };

    let mut padded_data = data.to_vec();
    for _ in 0..bytes_to_pad {
        padded_data.push(bytes_to_pad as u8);
    }

    padded_data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_perform_pkcs_7_padding_size_greater_than_data_size() {
        assert_eq!(
            pkcs_7(b"YELLOW SUBMARINE", 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
        assert_eq!(
            pkcs_7(b"YELLOW SUBMARINE12", 20),
            b"YELLOW SUBMARINE12\x02\x02"
        );
    }

    #[test]
    fn can_perform_pkcs_7_data_size_is_multiple_of_padding_size() {
        // Data size equals 1 * padding size
        assert_eq!(
            pkcs_7(b"YELLOW S", 8),
            b"YELLOW S\x08\x08\x08\x08\x08\x08\x08\x08"
        );
        // Data size equals 4 * padding size
        assert_eq!(
            pkcs_7(b"YELLOW SUBMARINE", 4),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }
}
