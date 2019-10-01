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
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_decrypt() {
        let mut file = File::open("data/7.txt").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        let encrypted = ByteArray::from_base64(&contents.replace("\n", "")).unwrap();
        let key = "YELLOW SUBMARINE";

        let bytes = decrypt(&encrypted, key).unwrap();
        let decrypted = str::from_utf8(&bytes).unwrap();

        assert!(decrypted.contains("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino"))
    }
}
