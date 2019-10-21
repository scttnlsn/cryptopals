use crate::encoding::ByteArray;
use itertools::Itertools;
use openssl::error::{ErrorStack};
use openssl::symm;
use openssl::symm::{Mode, Crypter};
use rand;
use rand::Rng;

const BLOCKSIZE: usize = 16;

#[derive(Debug, Clone, PartialEq)]
enum EncType {
    ECB,
    CBC,
}

pub fn pkcs7_pad(byte_array: &ByteArray, blocksize: usize) -> ByteArray {
    let len = blocksize as usize - (byte_array.bytes().len() % blocksize as usize);
    let mut padding = vec![len as u8; len];
    let mut bytes = byte_array.bytes().clone();
    bytes.append(&mut padding);
    ByteArray::from_bytes(bytes)
}

pub fn pkcs7_unpad(byte_array: &ByteArray) -> Option<ByteArray> {
    let bytes = byte_array.bytes();

    match bytes.last() {
        Some(padding_len) => {
            let padding: Vec<&u8> = bytes.iter().rev().take(*padding_len as usize).collect();
            if !padding.iter().all(|x| *x == padding_len) {
                return None
            }

            Some(ByteArray::from_bytes(bytes[0..(bytes.len() - *padding_len as usize)].to_vec()))
        },
        None => {
            Some(ByteArray::from_bytes(vec![]))
        }
    }
}

fn ecb_cipher(mode: Mode, key: &[u8], data: &[u8]) -> Result<ByteArray, ErrorStack> {
    let ecb = symm::Cipher::aes_128_ecb();

    let mut crypter = Crypter::new(ecb, mode, key, None)?;
    crypter.pad(false);

    let mut out = vec![0; data.len() + ecb.block_size()];
    let count = crypter.update(data, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;

    out.truncate(count + rest);
    Ok(ByteArray::from_bytes(out))
}

pub fn encrypt_ecb(data: &ByteArray, key: &[u8]) -> Result<ByteArray, ErrorStack> {
    let padded = pkcs7_pad(data, BLOCKSIZE);
    let bytes = ecb_cipher(Mode::Encrypt, key, &padded.bytes())?;
    Ok(bytes)
}

pub fn decrypt_ecb(data: &ByteArray, key: &[u8]) -> Result<ByteArray, ErrorStack> {
    let bytes = ecb_cipher(Mode::Decrypt, key, &data.bytes())?;
    match pkcs7_unpad(&bytes) {
        Some(unpadded) => Ok(unpadded),
        None => Ok(bytes),
    }
}

pub fn decrypt_cbc(data: &ByteArray, key: &[u8], iv: ByteArray) -> Result<ByteArray, ErrorStack> {
    let mut iv = iv;
    let mut output: Vec<u8> = Vec::new();

    for block in data.bytes().chunks(16).map(|bytes| ByteArray::from_bytes(bytes.to_vec())) {
        match ecb_cipher(Mode::Decrypt, key, &block.bytes()) {
            Ok(res) => {
                output.append(&mut res.xor(&iv).bytes());
                iv = block;
            },
            err => return err
        }
    }

    Ok(ByteArray::from_bytes(output))
}

pub fn encrypt_cbc(data: &ByteArray, key: &[u8], iv: ByteArray) -> Result<ByteArray, ErrorStack> {
    let mut iv = iv;
    let mut output: Vec<u8> = Vec::new();

    for block in data.bytes().chunks(16).map(|bytes| ByteArray::from_bytes(bytes.to_vec())) {
        match ecb_cipher(Mode::Encrypt, key, &block.xor(&iv).bytes()) {
            Ok(res) => {
                output.append(&mut res.bytes());
                iv = res;
            },
            err => return err
        }
    }

    Ok(ByteArray::from_bytes(output))
}

pub fn random_bytes(n: u32) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

pub fn random_key() -> Vec<u8> {
    random_bytes(BLOCKSIZE as u32)
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
    let padded = pkcs7_pad(&decrypted, BLOCKSIZE);
    let key = random_key();

    if rand::random() {
        // ECB
        encrypt_ecb(&padded, &key)
    } else {
        // CBC
        let iv = ByteArray::from_bytes(random_key());
        encrypt_cbc(&padded, &key, iv)
    }
}

fn unique_blocks(data: &ByteArray) -> usize {
    let bytes = data.bytes();
    let blocks = bytes.chunks(BLOCKSIZE as usize);
    let uniques: usize = blocks.unique().collect::<Vec<_>>().len();
    uniques
}

fn detection_oracle(data: &ByteArray) -> EncType {
    let bytes = data.bytes();
    let num_blocks = (data.len() / BLOCKSIZE as usize) as u32;

    for offset in 0..(BLOCKSIZE as usize) {
        let window = &bytes[offset..];
        let candidate = ByteArray::from_bytes(window.to_vec());
        let uniques = unique_blocks(&candidate) as i32;

        let duplicates = num_blocks as i32 - uniques;

        if duplicates > 0 {
            return EncType::ECB;
        }
    }

    EncType::CBC
}

fn prefix(prefix: &ByteArray, data: &ByteArray) -> ByteArray {
    let mut plaintext = prefix.bytes();
    let mut suffix = data.bytes();
    plaintext.append(&mut suffix);

    ByteArray::from_bytes(plaintext)
}

pub struct Oracle<'a> {
    pub data: &'a ByteArray,
    key: Vec<u8>,
    prefix: ByteArray,
}

impl<'a> Oracle<'a> {
    pub fn new(data: &'a ByteArray) -> Self {
        Oracle {
            key: random_key(),
            data: data,
            prefix: ByteArray::from_bytes(vec![]),
        }
    }

    pub fn new_prefixed(data: &'a ByteArray, n: u32) -> Self {
        Oracle {
            key: random_key(),
            data: data,
            prefix: ByteArray::from_bytes(random_bytes(n)),
        }
    }

    pub fn encrypt(&self, input: &ByteArray, offset: usize) -> Result<ByteArray, ErrorStack> {
        let bytes = self.data.bytes();

        let offset_bytes = bytes[offset..].to_vec();
        let offset_data = ByteArray::from_bytes(offset_bytes);

        encrypt_ecb(
            &prefix(
                &self.prefix,
                &prefix(input, &offset_data)
            ),
            &self.key
        )
    }
}

fn detect_blocksize(data: &ByteArray) -> Result<Option<usize>, ErrorStack> {
    let oracle = Oracle::new(data);

    for i in 1..20 {
        let bytes_cur = ByteArray::from_bytes(vec![b'A'; i]);
        let output_cur = oracle.encrypt(&bytes_cur, 0)?.bytes();

        let bytes_next = ByteArray::from_bytes(vec![b'A'; i + 1]);
        let output_next = oracle.encrypt(&bytes_next, 0)?.bytes();

        if &output_cur[0..i] == &output_next[0..i] {
            return Ok(Some(i));
        }
    }

    Ok(None)
}

pub fn detect_prefix_size(oracle: &Oracle) -> Result<usize, ErrorStack> {
    for i in 0..BLOCKSIZE {
        let input1 = ByteArray::from_bytes(vec![b'A'; i as usize]);
        let input2 = ByteArray::from_bytes(vec![b'A'; (i + 1) as usize]);

        let output1 = oracle.encrypt(&input1, 0)?.bytes();
        let output2 = oracle.encrypt(&input2, 0)?.bytes();

        if output1[0..(BLOCKSIZE as usize)] == output2[0..(BLOCKSIZE as usize)] {
            // when an extra padding byte results in the same first
            // block then we have found the prefix length
            return Ok(BLOCKSIZE - i);
        }
    }

    Ok(0)
}

pub fn crack_ecb(oracle: &Oracle) -> Result<ByteArray, ErrorStack> {
    let prefix_size = detect_prefix_size(&oracle)?;
    let prefix = ByteArray::from_bytes(vec![b'A'; (BLOCKSIZE - prefix_size - 1) as usize]);

    let mut decrypted: Vec<u8> = Vec::new();

    for i in 0..(oracle.data.bytes().len()) {
        let target = oracle.encrypt(&prefix, i)?.bytes();

        for b in 0..=255 {
            let mut prefix_bytes = prefix.bytes();
            prefix_bytes.push(b);

            let prefix = ByteArray::from_bytes(prefix_bytes);
            let result = oracle.encrypt(&prefix, i)?.bytes();

            if result[0..(BLOCKSIZE as usize)] == target[0..(BLOCKSIZE as usize)] {
                decrypted.push(b);
            }
        }
    }

    Ok(ByteArray::from_bytes(decrypted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_pkcs7_pad() {
        let s = ByteArray::from_string("YELLOW SUB");
        let res = pkcs7_pad(&s, 16);
        assert_eq!(res.string(), "YELLOW SUB\x06\x06\x06\x06\x06\x06");
    }

    #[test]
    fn test_pkcs7_unpad() {
        let s = ByteArray::from_string("YELLOW SUB\x06\x06\x06\x06\x06\x06");
        let res = pkcs7_unpad(&s).unwrap();
        assert_eq!(res.string(), "YELLOW SUB");

        let s = ByteArray::from_string("YELLOW SUB\x06\x06\x06\x06\x06\x05");
        let res = pkcs7_unpad(&s);
        assert_eq!(res, None);
    }

    #[test]
    fn test_decrypt() {
        let contents = fs::read_to_string("data/7.txt").unwrap();
        let encrypted = ByteArray::from_base64(&contents.replace("\n", "")).unwrap();
        let key = "YELLOW SUBMARINE".as_bytes();
        let decrypted = decrypt_ecb(&encrypted, key).unwrap().string();

        assert!(decrypted.contains("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino"))
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = "YELLOW SUBMARINE".as_bytes();
        let data = ByteArray::from_string("foobar");
        let encrypted = encrypt_ecb(&data, key).unwrap();
        let decrypted = decrypt_ecb(&encrypted, key).unwrap().string();

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
        assert_eq!(result.bytes().len() % 16, 0);
    }

    #[test]
    fn test_detection_oracle() {
        let data = ByteArray::from_string("YELLOW SUBMARINEYELLOW SUBMARINE");
        let key = "YELLOW SUBMARINE".as_bytes();

        let ecb = encrypt_ecb(&data, key).unwrap();
        assert_eq!(detection_oracle(&ecb), EncType::ECB);

        let iv = ByteArray::from_bytes(random_key());
        let cbc = encrypt_cbc(&data, key, iv).unwrap();
        assert_eq!(detection_oracle(&cbc), EncType::CBC);
    }

    #[test]
    fn test_detect_blocksize() {
        let data = ByteArray::from_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let blocksize = detect_blocksize(&data).unwrap();
        assert_eq!(blocksize, Some(BLOCKSIZE as usize));
    }

    #[test]
    fn test_crack_ecb() {
        let data = ByteArray::from_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let oracle = Oracle::new(&data);
        let decrypted = crack_ecb(&oracle).unwrap().string();

        assert!(decrypted.contains("Rollin' in my 5.0"));
        assert!(decrypted.contains("With my rag-top down so my hair can blow"));
        assert!(decrypted.contains("The girlies on standby waving just to say hi"));
        assert!(decrypted.contains("Did you stop? No, I just drove by"));
    }

    #[test]
    fn test_detect_prefix_size() {
        let data = ByteArray::from_string("hello world");
        let oracle = Oracle::new_prefixed(&data, 7);

        let size = detect_prefix_size(&oracle).unwrap();
        assert_eq!(size, 7);
    }

    #[test]
    fn test_crack_ecb_prefixed() {
        let data = ByteArray::from_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let oracle = Oracle::new_prefixed(&data, 5);
        let decrypted = crack_ecb(&oracle).unwrap().string();

        assert!(decrypted.contains("Rollin' in my 5.0"));
        assert!(decrypted.contains("With my rag-top down so my hair can blow"));
        assert!(decrypted.contains("The girlies on standby waving just to say hi"));
        assert!(decrypted.contains("Did you stop? No, I just drove by"));
    }
}
