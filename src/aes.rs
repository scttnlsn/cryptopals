use crate::cipher;
use crate::encoding::{ByteArray};
use itertools::Itertools;
use openssl::error::{ErrorStack};
use openssl::symm;
use openssl::symm::{Mode, Crypter};
use rand;
use rand::Rng;

#[derive(Debug, Clone, PartialEq)]
enum EncType {
    ECB,
    CBC,
}

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

fn decrypt_ecb(data: &ByteArray, key: &[u8], pad: bool) -> Result<ByteArray, ErrorStack> {
    ecb_cipher(Mode::Decrypt, key, &data.bytes(), pad).and_then(|bytes| {
        Ok(ByteArray::from_bytes(bytes))
    })
}

fn encrypt_ecb(data: &ByteArray, key: &[u8], pad: bool) -> Result<ByteArray, ErrorStack> {
    ecb_cipher(Mode::Encrypt, key, &data.bytes(), pad).and_then(|bytes| {
        Ok(ByteArray::from_bytes(bytes))
    })
}

fn decrypt_cbc(data: &ByteArray, key: &[u8], iv: ByteArray) -> Result<ByteArray, ErrorStack> {
    let mut iv = iv;
    let mut output: Vec<u8> = Vec::new();

    for block in data.bytes().chunks(16).map(|bytes| ByteArray::from_bytes(bytes.to_vec())) {
        match decrypt_ecb(&block, key, false) {
            Ok(res) => {
                output.append(&mut res.xor(&iv).bytes());
                iv = block;
            },
            err => return err
        }
    }

    Ok(ByteArray::from_bytes(output))
}

fn encrypt_cbc(data: &ByteArray, key: &[u8], iv: ByteArray) -> Result<ByteArray, ErrorStack> {
    let mut iv = iv;
    let mut output: Vec<u8> = Vec::new();

    for block in data.bytes().chunks(16).map(|bytes| ByteArray::from_bytes(bytes.to_vec())) {
        match encrypt_ecb(&block.xor(&iv), key, false) {
            Ok(res) => {
                output.append(&mut res.bytes());
                iv = res;
            },
            err => return err
        }
    }

    Ok(ByteArray::from_bytes(output))
}

fn random_bytes(n: u32) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

fn random_encrypt(data: &ByteArray) -> Result<ByteArray, ErrorStack> {
    let n = rand::thread_rng().gen_range(5, 11);
    let mut prefix = random_bytes(n);
    let mut suffix = random_bytes(n);

    let mut input: Vec<u8> = Vec::new();
    input.append(&mut prefix);
    input.append(&mut data.bytes().clone());
    input.append(&mut suffix);

    let decrypted = ByteArray::from_bytes(input);
    let padded = cipher::pkcs7(&decrypted, 16, 0);
    let key = random_bytes(16);

    if rand::random() {
        // ECB
        encrypt_ecb(&padded, &key, false)
    } else {
        // CBC
        let iv = ByteArray::from_bytes(random_bytes(16));
        encrypt_cbc(&padded, &key, iv)
    }
}

fn unique_blocks(data: &ByteArray) -> usize {
    let bytes = data.bytes();
    let blocks = bytes.chunks(16);
    let uniques: usize = blocks.unique().collect::<Vec<_>>().len();
    uniques
}

fn detection_oracle(data: &ByteArray) -> EncType {
    let bytes = data.bytes();
    let num_blocks = (data.len() / 16) as u32;

    for offset in 0..16 {
        let window = &bytes[offset..];
        let candidate = ByteArray::from_bytes(window.to_vec());
        let uniques = unique_blocks(&candidate) as u32;
        let duplicates = num_blocks - uniques;

        if duplicates > 0 {
            return EncType::ECB;
        }
    }

    EncType::CBC
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_decrypt() {
        let contents = fs::read_to_string("data/7.txt").unwrap();
        let encrypted = ByteArray::from_base64(&contents.replace("\n", "")).unwrap();
        let key = "YELLOW SUBMARINE".as_bytes();
        let decrypted = decrypt_ecb(&encrypted, key, true).unwrap().string();

        assert!(decrypted.contains("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino"))
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let data = ByteArray::from_string("foobar");
        let encrypted = encrypt_ecb(&data, key, true).unwrap();
        let decrypted = decrypt_ecb(&encrypted, key, true).unwrap().string();

        assert_eq!(decrypted, "foobar");
    }

    #[test]
    fn test_detect_aes() {
        let contents = fs::read_to_string("data/8.txt").unwrap();

        let candidates = contents.split("\n").filter(|line| line.len() > 0).map(|line| {
            ByteArray::from_hex(line).unwrap()
        });

        let mut unique_counts: Vec<_> = candidates.map(|candidate| {
            let count = unique_blocks(&candidate);
            (count, candidate)
        }).collect();

        unique_counts.sort_by(|(a, _), (b, _)| {
            a.cmp(b)
        });

        let (_, ecb) = &unique_counts[0];

        assert_eq!(ecb.hex(), "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");
    }

    #[test]
    fn test_decrypt_cbc() {
        let contents = fs::read_to_string("data/10.txt").unwrap();
        let encrypted = ByteArray::from_base64(&contents.replace("\n", "")).unwrap();
        let key = "YELLOW SUBMARINE".as_bytes();
        let iv = ByteArray::from_bytes(vec![0x00; 16]);
        let decrypted = decrypt_cbc(&encrypted, key, iv).unwrap().string();

        assert!(decrypted.contains("Play that funky music white boy"));
    }

    #[test]
    fn test_random_bytes() {
        let bytes = random_bytes(16);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn test_random_encrypt() {
        let data = ByteArray::from_string("YELLOW SUBMARINE");
        let result = random_encrypt(&data).unwrap();
        assert_eq!(result.bytes().len(), 32);
    }

    #[test]
    fn test_detection_oracle() {
        let data = ByteArray::from_string("YELLOW SUBMARINEYELLOW SUBMARINE");
        let key = "YELLOW SUBMARINE".as_bytes();

        let ecb = encrypt_ecb(&data, key, false).unwrap();
        assert_eq!(detection_oracle(&ecb), EncType::ECB);

        let iv = ByteArray::from_bytes(random_bytes(16));
        let cbc = encrypt_cbc(&data, key, iv).unwrap();
        assert_eq!(detection_oracle(&cbc), EncType::CBC);
    }
}
