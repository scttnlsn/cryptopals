use crate::encoding::{ByteArray};
use openssl::symm;
use std::str;

fn decrypt(encrypted: &ByteArray, key: &str) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = symm::Cipher::aes_128_ecb();

    symm::decrypt(
        cipher,
        key.as_bytes(),
        None,
        &encrypted.bytes
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_decrypt() {
        let contents = fs::read_to_string("data/7.txt").unwrap();
        let encrypted = ByteArray::from_base64(&contents.replace("\n", "")).unwrap();
        let key = "YELLOW SUBMARINE";

        let bytes = decrypt(&encrypted, key).unwrap();
        let decrypted = str::from_utf8(&bytes).unwrap();

        assert!(decrypted.contains("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino"))
    }

    #[test]
    fn test_detect_aes() {
        let contents = fs::read_to_string("data/8.txt").unwrap();

        let aes_encrypted: Vec<ByteArray> = contents.split("\n").filter_map(|line| {
            let encrypted = ByteArray::from_hex(line).unwrap();
            decrypt(&encrypted, "YELLOW SUBMARINE").ok()
        }).map(|bytes| {
            ByteArray::from_bytes(bytes)
        }).collect();

        assert_eq!(aes_encrypted.len(), 1);
    }
}
