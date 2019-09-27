use crate::encoding;
use regex::Regex;

fn english_score(s: &str) -> usize {
    let re = Regex::new(r"[a|e|i|o|u]").unwrap();
    re.find_iter(s).count()
}

pub fn find_key(encrypted: &encoding::ByteArray) -> encoding::ByteArray {
    let mut scores: Vec<(u32, usize)> = Vec::new();

    for b in 0..=255 {
        let key = encoding::ByteArray::from_bytes(vec![b; encrypted.len()]);
        let res = encrypted.xor(&key).string();
        scores.push((b, english_score(&res)));
    }

    scores.sort_by(|(_, a), (_, b)| b.cmp(a));
    encoding::ByteArray::from_bytes(vec![scores[0].0; encrypted.len()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_key() {
        let encrypted = encoding::ByteArray::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap();
        let key = find_key(&encrypted);
        let decrypted = encrypted.xor(&key).string();
        assert_eq!(decrypted, "Cooking MC's like a pound of bacon");
    }
}
