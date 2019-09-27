#[derive(Debug)]
pub struct ByteArray {
    bytes: Vec<u32>
}

impl ByteArray {
    pub fn from_bytes(bytes: Vec<u32>) -> ByteArray {
        ByteArray { bytes: bytes }
    }

    pub fn from_hex(hex: &str) -> Option<ByteArray> {
        let maybe_chars: Vec<Option<u32>> = hex
            .chars()
            .map(|c| c.to_digit(16))
            .collect();

        if maybe_chars.iter().any(|x| x.is_none()) {
            return None;
        }

        let chars: Vec<u32> = maybe_chars
            .iter()
            .map(|c| c.unwrap())
            .collect();

        let bytes = chars
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect();

        Some(ByteArray::from_bytes(bytes))
    }

    pub fn from_string(s: &str) -> ByteArray {
        let bytes = s.chars().map(|c| c as u32).collect();
        ByteArray::from_bytes(bytes)
    }

    pub fn len(&self) -> usize {
        return self.bytes.len();
    }

    pub fn string(&self) -> String {
        self.bytes.iter().map(|x| *x as u8 as char).collect()
    }

    pub fn hex(&self) -> String {
        let char_table: Vec<u8> = vec![(b'0'..=b'9'), (b'a'..=b'f')]
            .into_iter()
            .flatten()
            .collect();

        let mut result: Vec<char> = Vec::new();

        for byte in &self.bytes {
            let upper = (((*byte as u8 & 0xF0)) >> 4) as usize;
            let lower = (*byte as u8 & 0x0F) as usize;

            result.push(char_table[upper] as char);
            result.push(char_table[lower] as char);
        }

        result.iter().collect()
    }

    pub fn base64(&self) -> String {
        let char_table: Vec<u8> = vec![
            (b'A'..=b'Z').collect(),
            (b'a'..=b'z').collect(),
            (b'0'..=b'9').collect(),
            vec![b'+', b'/']
        ].into_iter().flatten().collect();

        let triplets: Vec<u32> = self.bytes
            .chunks(3)
            .map(|bytes| (bytes[0] << 16) | (bytes[1] << 8) | bytes[2])
            .collect();

        let mut result: Vec<char> = Vec::new();

        for triple in triplets {
            let bytes = vec![
                ((triple & 0xFC0000) >> 18) as usize,
                ((triple & 0x03F000) >> 12) as usize,
                ((triple & 0x000FC0) >> 6) as usize,
                (triple & 0x00003F) as usize
            ];

            let mut chars: Vec<char> = bytes.into_iter().map(|val| char_table[val] as char).collect();
            result.append(&mut chars);
        }

        result.iter().collect()
    }

    pub fn xor(&self, other: &ByteArray) -> ByteArray {
        let mut xored: Vec<u32> = Vec::new();

        for (b1, b2) in self.bytes.iter().zip(other.bytes.iter()) {
            xored.push(b1 ^ b2);
        }

        ByteArray { bytes: xored }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex() {
        let valid = "123ABC";
        assert!(ByteArray::from_hex(valid).is_some());

        let invalid = "123ABX";
        assert!(ByteArray::from_hex(invalid).is_none());
    }

    #[test]
    fn test_base64() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let byte_array = ByteArray::from_hex(hex).unwrap();
        let result = byte_array.base64();
        assert_eq!(result, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
    }

    #[test]
    fn test_xor() {
        let a = ByteArray::from_hex("1c0111001f010100061a024b53535009181c").unwrap();
        let b = ByteArray::from_hex("686974207468652062756c6c277320657965").unwrap();
        let xored = a.xor(&b).hex();
        assert_eq!(xored, "746865206b696420646f6e277420706c6179");
    }
}
