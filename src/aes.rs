use crate::encoding::ByteArray;
use itertools::Itertools;
use openssl::error::{ErrorStack};
use openssl::symm;
use openssl::symm::{Mode, Crypter};
use rand;

pub const BLOCKSIZE: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum EncMode {
    ECB,
    CBC,
}

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "decryption error: {}", error)]
    DecryptionError {
        error: ErrorStack,
    },
    #[fail(display = "invalid padding")]
    PaddingError,
}

impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Error {
        Error::DecryptionError { error: error }
    }
}

pub fn pkcs7_pad(byte_array: &ByteArray, blocksize: usize) -> ByteArray {
    let len = blocksize as usize - (byte_array.bytes().len() % blocksize as usize);
    let mut bytes = byte_array.bytes().clone();
    bytes.extend(vec![len as u8; len]);
    ByteArray::from_bytes(bytes)
}

pub fn pkcs7_unpad(byte_array: &ByteArray) -> Result<ByteArray, Error> {
    let bytes = byte_array.bytes();

    match bytes.last() {
        Some(padding_len) => {
            if *padding_len == 0 {
                return Err(Error::PaddingError);
            }

            let padding = bytes
                .iter()
                .rev()
                .take(*padding_len as usize)
                .collect::<Vec<&u8>>();

            if !padding.iter().all(|x| *x == padding_len) {
                return Err(Error::PaddingError);
            }

            let unpadded = bytes[0..(bytes.len() - *padding_len as usize)].to_vec();
            Ok(ByteArray::from_bytes(unpadded))
        },
        None => {
            Ok(ByteArray::from_bytes(vec![]))
        }
    }
}

pub fn ecb_cipher(mode: Mode, key: &[u8], data: &[u8]) -> Result<ByteArray, Error> {
    let ecb = symm::Cipher::aes_128_ecb();

    let mut crypter = Crypter::new(ecb, mode, key, None)?;
    crypter.pad(false);

    let mut out = vec![0; data.len() + ecb.block_size()];
    let count = crypter.update(data, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;

    out.truncate(count + rest);
    Ok(ByteArray::from_bytes(out))
}

pub fn encrypt_ecb(data: &ByteArray, key: &[u8]) -> Result<ByteArray, Error> {
    let padded = pkcs7_pad(data, BLOCKSIZE);
    let bytes = ecb_cipher(Mode::Encrypt, key, &padded.bytes())?;
    Ok(bytes)
}

pub fn decrypt_ecb(data: &ByteArray, key: &[u8]) -> Result<ByteArray, Error> {
    let bytes = ecb_cipher(Mode::Decrypt, key, &data.bytes())?;
    pkcs7_unpad(&bytes)
}

pub fn decrypt_cbc(data: &ByteArray, key: &[u8], iv: ByteArray) -> Result<ByteArray, Error> {
    let mut iv = iv;
    let mut output = Vec::new();

    for block in data.bytes().chunks(16).map(|bytes| ByteArray::from_bytes(bytes.to_vec())) {
        let res = ecb_cipher(Mode::Decrypt, key, &block.bytes())?;
        output.extend(res.xor(&iv).bytes());
        iv = block;
    }

    Ok(ByteArray::from_bytes(output))
}

pub fn encrypt_cbc(data: &ByteArray, key: &[u8], iv: ByteArray) -> Result<ByteArray, Error> {
    let mut iv = iv;
    let mut output = Vec::new();

    for block in data.bytes().chunks(16).map(|bytes| ByteArray::from_bytes(bytes.to_vec())) {
        let res = ecb_cipher(Mode::Encrypt, key, &block.xor(&iv).bytes())?;
        output.extend(res.bytes());
        iv = res;
    }

    Ok(ByteArray::from_bytes(output))
}

#[derive(Debug, PartialEq)]
struct CBC {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl CBC {
    pub fn new() -> Self {
        CBC {
            key: random_key(),
            iv: random_bytes(BLOCKSIZE),
        }
    }

    pub fn encrypt(&self, data: &ByteArray) -> Result<ByteArray, Error> {
        let padded = pkcs7_pad(&data, BLOCKSIZE);
        encrypt_cbc(&padded, &self.key, ByteArray::from_bytes(self.iv.to_vec()))
    }

    pub fn decrypt(&self, ciphertext: &ByteArray) -> Result<ByteArray, Error> {
        let data = decrypt_cbc(&ciphertext, &self.key, ByteArray::from_bytes(self.iv.to_vec()))?;
        pkcs7_unpad(&data)
    }

    pub fn check_padding(&self, ciphertext: &ByteArray) -> Result<bool, Error> {
        let data = decrypt_cbc(&ciphertext, &self.key, ByteArray::from_bytes(self.iv.to_vec()))?;
        Ok(pkcs7_unpad(&data).is_ok())
    }
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

pub fn random_key() -> Vec<u8> {
    random_bytes(BLOCKSIZE)
}

fn unique_blocks(data: &ByteArray) -> usize {
    let bytes = data.bytes();
    let blocks = bytes.chunks(BLOCKSIZE as usize);
    let uniques: usize = blocks.unique().collect::<Vec<_>>().len();
    uniques
}

fn detect_mode(data: &ByteArray) -> EncMode {
    let bytes = data.bytes();
    let num_blocks = (data.len() / BLOCKSIZE as usize) as u32;

    for offset in 0..(BLOCKSIZE as usize) {
        let window = &bytes[offset..];
        let candidate = ByteArray::from_bytes(window.to_vec());
        let uniques = unique_blocks(&candidate) as i32;

        let duplicates = num_blocks as i32 - uniques;

        if duplicates > 0 {
            return EncMode::ECB;
        }
    }

    EncMode::CBC
}

#[derive(Debug)]
pub struct Oracle<'a> {
    data: &'a ByteArray,
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

    pub fn new_prefixed(data: &'a ByteArray, n: usize) -> Self {
        Oracle {
            key: random_key(),
            data: data,
            prefix: ByteArray::from_bytes(random_bytes(n)),
        }
    }

    pub fn encrypt(&self, input: &ByteArray) -> Result<ByteArray, Error> {
        encrypt_ecb(
            &self.data.prefix(&input.prefix(&self.prefix)),
            &self.key
        )
    }
}

fn detect_blocksize(data: &ByteArray) -> Result<Option<usize>, Error> {
    let oracle = Oracle::new(data);

    for i in 1..20 {
        let bytes_cur = ByteArray::from_bytes(vec![b'A'; i]);
        let output_cur = oracle.encrypt(&bytes_cur)?.bytes();

        let bytes_next = ByteArray::from_bytes(vec![b'A'; i + 1]);
        let output_next = oracle.encrypt(&bytes_next)?.bytes();

        if &output_cur[0..i] == &output_next[0..i] {
            return Ok(Some(i));
        }
    }

    Ok(None)
}

fn detect_data_len(oracle: &Oracle) -> Result<usize, Error> {
    let base_length = oracle.encrypt(&ByteArray::from_bytes(vec![]))?.bytes().len();
    let mut i = 1;

    loop {
        let input = ByteArray::from_bytes(vec![b'A'; i]);
        let output = oracle.encrypt(&input)?;
        let size = output.bytes().len();

        if size != base_length {
            return Ok(size - i)
        }

        i += 1;
    }
}

pub fn detect_prefix_len(oracle: &Oracle) -> Result<usize, Error> {
    for i in 0..BLOCKSIZE {
        let input1 = ByteArray::from_bytes(vec![b'A'; i as usize]);
        let input2 = ByteArray::from_bytes(vec![b'A'; (i + 1) as usize]);

        let output1 = oracle.encrypt(&input1)?.bytes();
        let output2 = oracle.encrypt(&input2)?.bytes();

        if output1[0..(BLOCKSIZE as usize)] == output2[0..(BLOCKSIZE as usize)] {
            // when an extra padding byte results in the same first
            // block then we have found the prefix length
            return Ok(BLOCKSIZE - i);
        }
    }

    Ok(0)
}

pub fn crack_ecb(oracle: &Oracle) -> Result<ByteArray, Error> {
    let data_len = detect_data_len(&oracle)?;
    let prefix_len = detect_prefix_len(&oracle)?;

    let mut decrypted: Vec<u8> = Vec::new();

    for _ in 0..data_len {
        let len = decrypted.len();

        // make sure that the next unknown byte is at the end of the block
        let pad_len = (BLOCKSIZE - ((len + prefix_len + 1) % BLOCKSIZE)) % BLOCKSIZE;
        let pad = ByteArray::from_bytes(vec![b'A'; pad_len]);

        let block_num = (len + prefix_len) / BLOCKSIZE;
        let target_start = block_num * BLOCKSIZE;
        let target_end = target_start + BLOCKSIZE;

        let target = oracle.encrypt(&pad)?.bytes();

        for b in 0..=255 {
            let mut bytes = pad.bytes();
            bytes.extend(decrypted.to_vec());
            bytes.push(b);

            let input = ByteArray::from_bytes(bytes);
            let result = oracle.encrypt(&input)?.bytes();

            if result[target_start..target_end] == target[target_start..target_end] {
                decrypted.push(b);
                break;
             }
        }
    }

    Ok(ByteArray::from_bytes(decrypted))
}

fn crack_cbc(cbc: &CBC, ciphertext: &ByteArray) -> Result<ByteArray, Error> {
    let mut decrypted: Vec<u8> = Vec::new();

    let bytes = ciphertext.bytes();
    let mut blocks: Vec<&[u8]> = bytes.chunks(BLOCKSIZE).collect();

    // assume the attacker has the CBC IV
    blocks.insert(0, &cbc.iv);

    for blocks in blocks.windows(2) {
        let mut decrypted_block: Vec<u8> = Vec::new();

        let c1 = blocks[0].to_vec();
        let c2 = blocks[1].to_vec();

        let mut bytes = c1.to_vec();
        bytes.extend(c2.to_vec());
        let valid_padding = cbc.check_padding(&ByteArray::from_bytes(bytes))?;

        // c2 must be the last block since it has valid padding w/o modification
        let last_block = valid_padding;

        let mut pad_val = 0;

        // n=1 means we're cracking the rightmost byte of a block
        // n=2 means we're cracking the 2nd rightmost byte of a block
        // etc.
        for n in 1..=(BLOCKSIZE) {
            for i in 0..=255 {
                if i == n && !(last_block && i == pad_val) {
                    continue;
                }

                let mut pad_bytes = vec![0 as u8; BLOCKSIZE - n];
                pad_bytes.extend(vec![n as u8; n]);
                let pad_mask = ByteArray::from_bytes(pad_bytes);

                let mut val_bytes = vec![0 as u8; BLOCKSIZE - n];
                val_bytes.push(i as u8);
                val_bytes.extend(decrypted_block.to_vec());
                let val_mask = ByteArray::from_bytes(val_bytes);

                let c1_masked = ByteArray::from_bytes(c1.to_vec()).xor(&pad_mask).xor(&val_mask);

                let mut bytes = c1_masked.bytes();
                bytes.extend(c2.to_vec());

                let valid_padding = cbc.check_padding(&ByteArray::from_bytes(bytes))?;
                if valid_padding {
                    decrypted_block.insert(0, i as u8);

                    if last_block && n == 1 {
                        // last byte of last block must be pad value
                        pad_val = i;
                    }

                    break;
                }
            }
        }

        decrypted.extend(decrypted_block);
    }

    let result = ByteArray::from_bytes(decrypted);
    pkcs7_unpad(&result)
}

#[derive(Debug, PartialEq)]
struct UserData<'a> {
    data: String,
    cbc: &'a CBC,
}

impl<'a> UserData<'a> {
    pub fn new(input: &str, cbc: &'a CBC) -> Self {
        let sanitized = input.replace("=", "").replace(";", "");
        let data = format!("comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon", sanitized);

        UserData {
            data: data,
            cbc: cbc,
        }
    }

    pub fn decrypt(ciphertext: &ByteArray, cbc: &'a CBC) -> Result<Self, Error> {
        let data = cbc.decrypt(ciphertext)?;

        Ok(UserData {
            data: data.string(),
            cbc: cbc,
        })
    }

    pub fn encrypt(&self) -> Result<ByteArray, Error> {
        let data = ByteArray::from_string(&self.data);
        self.cbc.encrypt(&data)
    }

    pub fn is_admin(&self) -> bool {
        self.data.contains(";admin=true;")
    }
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
        assert!(res.is_err());

        let s = ByteArray::from_string("YELLOW SUBMARIN\x02");
        let res = pkcs7_unpad(&s);
        assert!(res.is_err());

        let s = ByteArray::from_string("YELLOW SUBMARIN\x00");
        let res = pkcs7_unpad(&s);
        assert!(res.is_err());

        let s = ByteArray::from_string("YELLOW SUBMARI\x01\x01");
        let res = pkcs7_unpad(&s).unwrap();
        assert_eq!(res.string(), "YELLOW SUBMARI\x01");
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
    fn test_detect_mode() {
        let data = ByteArray::from_string("YELLOW SUBMARINEYELLOW SUBMARINE");
        let key = "YELLOW SUBMARINE".as_bytes();

        let ecb = encrypt_ecb(&data, key).unwrap();
        assert_eq!(detect_mode(&ecb), EncMode::ECB);

        let iv = ByteArray::from_bytes(random_key());
        let cbc = encrypt_cbc(&data, key, iv).unwrap();
        assert_eq!(detect_mode(&cbc), EncMode::CBC);
    }

    #[test]
    fn test_detect_blocksize() {
        let data = ByteArray::from_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let blocksize = detect_blocksize(&data).unwrap();
        assert_eq!(blocksize, Some(BLOCKSIZE as usize));
    }

    #[test]
    fn test_crack_ecb_unprefixed() {
        let data = ByteArray::from_base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let oracle = Oracle::new(&data);
        let decrypted = crack_ecb(&oracle).unwrap().string();

        assert!(decrypted.contains("Rollin' in my 5.0"));
        assert!(decrypted.contains("With my rag-top down so my hair can blow"));
        assert!(decrypted.contains("The girlies on standby waving just to say hi"));
        assert!(decrypted.contains("Did you stop? No, I just drove by"));
    }

    #[test]
    fn test_detect_prefix_len() {
        let data = ByteArray::from_string("hello world");
        let oracle = Oracle::new_prefixed(&data, 7);

        let size = detect_prefix_len(&oracle).unwrap();
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

    #[test]
    fn test_user_profile() {
        let cbc = CBC::new();
        let data = "foo;admin=true;";
        let userdata = UserData::new(data, &cbc);

        assert_eq!(userdata.is_admin(), false);

        let ciphertext = userdata.encrypt().unwrap();
        let userdata2 = UserData::decrypt(&ciphertext, &cbc).unwrap();

        assert_eq!(userdata, userdata2)
    }

    #[test]
    fn test_user_profile_admin() {
        let padding = ByteArray::from_string("AAAAAAAAAAAAAAAA");
        let data = ByteArray::from_string(";admin=true;AAAA");

        // mask lines up w/ ';' and '=' bytes of data
        let mask = ByteArray::from_bytes(vec![1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0]);

        let mut bytes = padding.bytes();

        // xor the data w/ mask (this will be reversed when decrypting)
        bytes.extend(data.xor(&mask).bytes());

        let input = ByteArray::from_bytes(bytes);

        let cbc = CBC::new();
        let userdata = UserData::new(&input.string(), &cbc);
        assert_eq!(userdata.is_admin(), false);

        let encrypted = userdata.encrypt().unwrap();

        let mut bytes = encrypted.bytes();

        // xor the encrypted padding block
        // these bit changes will be present in next (data) block when decrypting
        let block = ByteArray::from_bytes(bytes[(BLOCKSIZE * 2)..(BLOCKSIZE * 3)].to_vec());
        let xored_block = block.xor(&mask);
        bytes.splice((BLOCKSIZE * 2)..(BLOCKSIZE * 3), xored_block.bytes());

        let res = UserData::decrypt(&ByteArray::from_bytes(bytes), &cbc).unwrap();
        assert_eq!(res.is_admin(), true);
    }

    #[test]
    fn test_crack_cbc() {
        let cbc = CBC::new();

        let test_inputs = vec![
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ];

        for test in test_inputs {
            let input = ByteArray::from_base64(test).unwrap();
            let ciphertext = cbc.encrypt(&input).unwrap();
            let plaintext = crack_cbc(&cbc, &ciphertext).unwrap().string();
            assert_eq!(plaintext, input.string());
        }
    }
}
