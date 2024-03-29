use crate::encoding::{ByteArray};
use std::f64;
use std::str;

#[derive(Debug, Clone)]
pub struct Score<'a> {
    encrypted: &'a ByteArray,
    decrypted: ByteArray,
    key: ByteArray,
    score: f64,
}

pub fn letter_freq(c: char) -> f64 {
    match c {
        'a' => 8.167,
        'b' => 1.492,
        'c' => 2.782,
        'd' => 4.253,
        'e' => 12.702,
        'f' => 2.228,
        'g' => 2.015,
        'h' => 6.094,
        'i' => 6.966,
        'j' => 0.153,
        'k' => 0.772,
        'l' => 4.025,
        'm' => 2.406,
        'n' => 6.749,
        'o' => 7.507,
        'p' => 1.929,
        'q' => 0.095,
        'r' => 5.987,
        's' => 6.327,
        't' => 9.056,
        'u' => 2.758,
        'v' => 0.978,
        'w' => 2.360,
        'x' => 0.150,
        'y' => 1.974,
        'z' => 0.074,
        ' ' => 13.0,
        _ => 0.0
    }
}

fn english_score(s: &str) -> f64 {
    let sum_squares: f64 = s.chars().map(|c| {
        letter_freq(c.to_ascii_lowercase()).powi(2)
    }).sum();

    sum_squares.sqrt()
}

pub fn find_key(encrypted: &ByteArray) -> Score {
    let mut scores: Vec<Score> = (0..=255).map(|b| {
        let key = ByteArray::from_bytes(vec![b as u8; encrypted.len()]);
        let decrypted = encrypted.xor(&key);
        let score = english_score(&decrypted.string());

        Score {
            encrypted: encrypted,
            key: key,
            decrypted: decrypted,
            score: score
        }
    }).collect();

    scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    scores[0].clone()
}

pub fn encrypt(decrypted: &ByteArray, key: &str) -> ByteArray {
    let repeats = decrypted.len() / key.len() + 1;
    let mut key = key.repeat(repeats);
    key.truncate(decrypted.len());

    decrypted.xor(&ByteArray::from_string(&key))
}

pub fn keysize(ciphertext: &ByteArray) -> usize {
    let mut results: Vec<(usize, f64)> = (2..=40).map(|size| {
        let chunks: Vec<Vec<u8>> = ciphertext
            .bytes()
            .chunks(size)
            .map(|chunk| chunk.to_vec())
            .take(4)
            .collect();

        let a = ByteArray::from_bytes(chunks[0].to_vec());
        let b = ByteArray::from_bytes(chunks[1].to_vec());
        let c = ByteArray::from_bytes(chunks[2].to_vec());
        let d = ByteArray::from_bytes(chunks[3].to_vec());

        let numer = (
            a.hamming_distance(&b)
                + a.hamming_distance(&c)
                + a.hamming_distance(&d)
                + b.hamming_distance(&c)
                + b.hamming_distance(&d)
                + c.hamming_distance(&d)) as f64;

        let denom = (size * 6) as f64;

        (size, numer / denom)
    }).collect();

    results.sort_by(|a, b| {
        a.1.partial_cmp(&b.1).unwrap()
    });

    results[0].0
}

pub fn find_key_of_size(ciphertext: &ByteArray, keysize: usize) -> ByteArray {
    let bytes = ciphertext.bytes();
    let blocks: Vec<&[u8]> = bytes.chunks(keysize).collect();

    let mut key: Vec<u8> = Vec::new();

    for i in 0..keysize {
        let mut transposed: Vec<u8> = Vec::new();

        for block in &blocks {
            if i < block.len() {
                transposed.push(block[i]);
            }
        }

        let transposed_block = ByteArray::from_bytes(transposed);

        let score = find_key(&transposed_block);
        key.push(score.key.bytes()[0])
    }

    ByteArray::from_bytes(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_find_key() {
        let encrypted = ByteArray::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        let score = find_key(&encrypted);
        let decrypted = encrypted.xor(&score.key).string();
        assert_eq!(decrypted, "Cooking MC's like a pound of bacon");
    }

    #[test]
    fn test_encrypt() {
        let decrypted = ByteArray::from_string("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
        let key = "ICE";
        let result = encrypt(&decrypted, key).hex();
        assert_eq!(result, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    }

    #[test]
    fn test_detect_single_character() {
        let contents = fs::read_to_string("data/4.txt").unwrap();
        let encrypted: Vec<ByteArray> = contents.split("\n").map(|line| {
            ByteArray::from_hex(line).unwrap()
        }).collect();

        let mut scores: Vec<Score> = encrypted.iter().map(|x| find_key(&x)).collect();

        scores.sort_by(|a, b| {
            b.score.partial_cmp(&a.score).unwrap()
        });

        assert_eq!(scores[0].decrypted.string(), "Now that the party is jumping\n");
    }

    #[test]
    fn test_break_repeating_key_xor() {
        let contents = fs::read_to_string("data/6.txt").unwrap();
        let ciphertext = ByteArray::from_base64(&contents.replace("\n", "")).unwrap();
        let size = keysize(&ciphertext);
        assert_eq!(size, 29);

        let key = find_key_of_size(&ciphertext, size);
        let decrypted = encrypt(&ciphertext, &key.string());
        assert!(decrypted.string().contains("VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino"))
    }
}
