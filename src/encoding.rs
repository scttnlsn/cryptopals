#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ByteArray(Vec<u8>);

impl Into<Vec<u8>> for ByteArray {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(bytes: Vec<u8>) -> Self {
        ByteArray(bytes)
    }
}

impl ByteArray {
    pub fn from_bytes(bytes: Vec<u8>) -> ByteArray {
        ByteArray(bytes)
    }

    pub fn from_hex(hex: &str) -> Option<ByteArray> {
        let maybe_chars = hex
            .chars()
            .map(|c| c.to_digit(16))
            .collect::<Vec<Option<u32>>>();

        if maybe_chars.iter().any(|x| x.is_none()) {
            return None;
        }

        let chars = maybe_chars
            .iter()
            .map(|c| c.unwrap() as u8)
            .collect::<Vec<u8>>();

        let bytes = chars
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect();

        Some(ByteArray::from_bytes(bytes))
    }

    pub fn from_base64(s: &str) -> Result<ByteArray, base64::DecodeError> {
        let bytes = base64::decode(s)?;
        Ok(ByteArray::from_bytes(bytes.iter().map(|&x| x as u8).collect()))
    }

    pub fn from_string(s: &str) -> ByteArray {
        let bytes = s.chars().map(|c| c as u8).collect();
        ByteArray::from_bytes(bytes)
    }

    pub fn len(&self) -> usize {
        return self.bytes().len();
    }

    pub fn bytes(&self) -> Vec<u8> {
        let Self(bytes) = &*self;
        bytes.to_vec()
    }

    pub fn string(&self) -> String {
        self.bytes().iter().map(|x| *x as u8 as char).collect()
    }

    pub fn hex(&self) -> String {
        let char_table: Vec<u8> = vec![(b'0'..=b'9'), (b'a'..=b'f')]
            .into_iter()
            .flatten()
            .collect();

        let mut result: Vec<char> = Vec::new();

        for byte in &self.bytes() {
            let upper = (((*byte as u8 & 0xF0)) >> 4) as usize;
            let lower = (*byte as u8 & 0x0F) as usize;

            result.push(char_table[upper] as char);
            result.push(char_table[lower] as char);
        }

        result.iter().collect()
    }

    pub fn base64(&self) -> String {
        let char_table: Vec<u8> = vec![
            (b'A'..=b'Z'),
            (b'a'..=b'z'),
            (b'0'..=b'9'),
            (b'+'..=b'+'),
            (b'/'..=b'/'),
        ].into_iter().flatten().collect();

        let triplets: Vec<u32> = self.bytes()
            .chunks(3)
            .map(|bytes| ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32)
            .collect();

        let mut result: Vec<char> = Vec::new();

        for triple in triplets {
            let bytes = vec![
                ((triple & 0xFC0000) >> 18) as usize,
                ((triple & 0x03F000) >> 12) as usize,
                ((triple & 0x000FC0) >> 6) as usize,
                (triple & 0x00003F) as usize
            ];

            let chars: Vec<char> = bytes.into_iter().map(|val| char_table[val] as char).collect();
            result.extend(chars);
        }

        result.iter().collect()
    }

    pub fn xor(&self, other: &ByteArray) -> ByteArray {
        let bytes = self.bytes().iter().zip(other.bytes().iter()).map(|(a, b)| a ^ b).collect();
        ByteArray(bytes)
    }

    pub fn hamming_distance(&self, other: &ByteArray) -> u32 {
        let mut count = 0;

        for byte in self.xor(other).bytes() {
            for i in 0..8 {
                if ((byte >> i) & 0x1) > 0 {
                    count += 1;
                }
            }
        }

        count
    }

    pub fn prefix(&self, prefix: &ByteArray) -> ByteArray {
        let mut bytes = prefix.bytes();
        bytes.extend(self.bytes());
        ByteArray::from_bytes(bytes)
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

    #[test]
    fn test_hamming_distance() {
        let a = ByteArray::from_string("this is a test");
        let b = ByteArray::from_string("wokka wokka!!!");
        let result = a.hamming_distance(&b);
        assert_eq!(result, 37);
    }
}
