use crate::aes;
use crate::cipher;
use crate::encoding::ByteArray;
use openssl::symm::Mode;

struct CTR {
    key: Vec<u8>,
    nonce: Vec<u8>,
}

impl CTR {
    pub fn new(key: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self {
            key: key,
            nonce: nonce,
        }
    }

    pub fn cipher(&self, data: &ByteArray) -> Result<ByteArray, aes::Error> {
        let mut output = Vec::new();

        let bytes = data.bytes();
        let blocks = bytes
            .chunks(aes::BLOCKSIZE)
            .map(|bytes| bytes.to_vec())
            .map(ByteArray::from_bytes);

        for (counter, block) in blocks.enumerate() {
            let nonce_bytes = self.nonce_bytes(counter as u32);
            let ciphered = aes::ecb_cipher(Mode::Encrypt, &self.key, &nonce_bytes)?;
            output.extend(block.xor(&ciphered).bytes());
        }

        Ok(ByteArray::from_bytes(output))
    }

    fn nonce_bytes(&self, counter: u32) -> Vec<u8> {
        let mut bytes = self.nonce.to_vec();

        // counter in little-endian byte order
        bytes.push(((counter & 0x000000FF) >> 0) as u8);
        bytes.push(((counter & 0x0000FF00) >> 1) as u8);
        bytes.push(((counter & 0x00FF0000) >> 2) as u8);
        bytes.push(((counter & 0xFF000000) >> 3) as u8);

        // since counter is only a u32
        bytes.extend(vec![0, 0, 0, 0]);

        bytes
    }
}

fn crack_fixed_nonce(ciphertexts: &Vec<ByteArray>) -> Vec<ByteArray> {
    let n = ciphertexts.len();
    let mut results = Vec::new();

    let ciphertext_bytes = ciphertexts.iter().map(|ciphertext| {
        ciphertext.bytes()
    }).collect::<Vec<Vec<u8>>>();

    for index in 0..n {
        let mut plaintext = Vec::new();
        let ciphertext = &ciphertext_bytes[index];

        for i in 0.. {
            if i >= ciphertext.len() {
                break;
            }

            let mut max_score = 0.0;
            let mut best_guess = 0;

            for guess_byte in 0..=255 {
                let mut score = 0.0;

                for j in 0..n {
                    if i >= ciphertexts[j].len() {
                        continue;
                    }

                    let plaintext_byte = guess_byte ^ ciphertext_bytes[j][i];
                    score += cipher::letter_freq(plaintext_byte as char);
                }

                if score > max_score {
                    max_score = score;
                    best_guess = guess_byte;
                }
            }

            plaintext.push(ciphertext[i] ^ best_guess);
        }

        results.push(ByteArray::from_bytes(plaintext))
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_ctr_cipher() {
        let ctr = CTR::new(aes::random_key(), aes::random_bytes(8));
        let plaintext = ByteArray::from_string("testing");
        let ciphertext = ctr.cipher(&plaintext).unwrap();

        let res = ctr.cipher(&ciphertext).unwrap();
        assert_eq!(res.string(), "testing");

        let key = "YELLOW SUBMARINE".as_bytes().to_vec();
        let ctr = CTR::new(key, vec![0; 8]);
        let ciphertext = ByteArray::from_base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").unwrap();
        let plaintext = ctr.cipher(&ciphertext).unwrap();

        assert_eq!(plaintext.string(), "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ");
    }

    #[test]
    fn test_break_fixed_nonce() {
        let ctr = CTR::new(aes::random_key(), aes::random_bytes(8));

        let contents = fs::read_to_string("data/19.txt").unwrap();

        let plaintexts = contents.split("\n").filter(|line| line.len() > 0).map(|line| {
            ByteArray::from_base64(line).unwrap()
        }).collect::<Vec<ByteArray>>();

        let ciphertexts: Vec<ByteArray> = plaintexts.iter().map(|plaintext| {
            ctr.cipher(plaintext).unwrap()
        }).collect();

        let results = crack_fixed_nonce(&ciphertexts);

        assert_eq!(results[0].string(), "i have met them at close of day");
        assert_eq!(results[1].string(), "coming with vivid faces");
    }
}
