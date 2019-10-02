use crate::encoding::{ByteArray};
use openssl::error::{ErrorStack};
use openssl::symm;
use openssl::symm::{Cipher, Mode, Crypter};
use std::str;

fn ecb_cipher(mode: Mode, key: &[u8], data: &[u8], pad: bool) -> Result<Vec<u8>, ErrorStack> {
    let ecb = symm::Cipher::aes_128_ecb();

    let mut crypter = Crypter::new(ecb, mode, key, None)?;
    crypter.pad(pad);

    let mut out = vec![0; data.len() + ecb.block_size()];
    let count = crypter.update(data, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;

    out.truncate(count + rest);
    Ok(out)
}

fn decrypt_ecb(data: &ByteArray, key: &str, pad: bool) -> Result<ByteArray, ErrorStack> {
    ecb_cipher(Mode::Decrypt, key.as_bytes(), &data.bytes, pad).and_then(|bytes| {
        Ok(ByteArray::from_bytes(bytes))
    })
}

fn encrypt_ecb(data: &ByteArray, key: &str, pad: bool) -> Result<ByteArray, ErrorStack> {
    ecb_cipher(Mode::Encrypt, key.as_bytes(), &data.bytes, pad).and_then(|bytes| {
        Ok(ByteArray::from_bytes(bytes))
    })
}

fn decrypt_cbc(data: &ByteArray, key: &str, iv: ByteArray) -> Result<ByteArray, ErrorStack> {
    let mut iv = iv;
    let mut output: Vec<u8> = Vec::new();

    for block in data.bytes.chunks(16).map(|bytes| ByteArray::from_bytes(bytes.to_vec())) {
        match decrypt_ecb(&block, key, false) {
            Ok(res) => {
                output.append(&mut res.xor(&iv).bytes);
                iv = block;
            },
            err => return err
        }
    }

    Ok(ByteArray::from_bytes(output))
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
        let decrypted = decrypt_ecb(&encrypted, key, true).unwrap().string();

        assert!(decrypted.contains("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino"))
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = "YELLOW SUBMARINE";
        let data = ByteArray::from_string("foobar");
        let encrypted = encrypt_ecb(&data, key, true).unwrap();
        let decrypted = decrypt_ecb(&encrypted, key, true).unwrap().string();

        assert_eq!(decrypted, "foobar");
    }

    #[test]
    fn test_detect_aes() {
        let contents = fs::read_to_string("data/8.txt").unwrap();

        let aes_encrypted: Vec<ByteArray> = contents.split("\n").filter_map(|line| {
            let encrypted = ByteArray::from_hex(line).unwrap();
            decrypt_ecb(&encrypted, "YELLOW SUBMARINE", true).ok()
        }).collect();

        assert_eq!(aes_encrypted.len(), 1);
    }

    #[test]
    fn test_decrypt_cbc() {
        let contents = fs::read_to_string("data/10.txt").unwrap();
        let encrypted = ByteArray::from_base64(&contents.replace("\n", "")).unwrap();
        let key = "YELLOW SUBMARINE";
        let iv = ByteArray::from_bytes(vec![0x00; 16]);
        let decrypted = decrypt_cbc(&encrypted, key, iv).unwrap().string();

        assert!(decrypted.contains("Play that funky music white boy"));
    }
}
