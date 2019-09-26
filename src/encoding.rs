#[derive(Debug)]
pub struct ByteArray {
    bytes: Vec<u32>
}

impl ByteArray {
    pub fn from_bytes(bytes: Vec<u32>) -> ByteArray {
        ByteArray { bytes: bytes }
    }

    pub fn from_hex(hex: &str) -> ByteArray {
        let chars: Vec<u32> = hex
            .chars()
            .map(|c| c.to_digit(16).unwrap()) // TODO: method should return optional
            .collect();

        let bytes = chars
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect();

        ByteArray::from_bytes(bytes)
    }

    pub fn len(&self) -> usize {
        return self.bytes.len();
    }

    pub fn string(&self) -> String {
        self.bytes.iter().map(|x| *x as u8 as char).collect()
    }

    pub fn hex(&self) -> String {
        let ranges: Vec<Vec<u8>> = vec![
            (b'0'..=b'9').collect(),
            (b'a'..=b'f').collect()
        ];

        let char_table: Vec<char> = ranges
            .iter()
            .flatten()
            .map(|x| *x as char)
            .collect();

        let mut result: Vec<char> = Vec::new();

        for byte in &self.bytes {
            let upper = (*byte as u8 & 0xF0) >> 4;
            let lower = *byte as u8 & 0x0F;

            result.push(char_table[upper as usize]);
            result.push(char_table[lower as usize]);
        }

        result.iter().collect()
    }

    pub fn base64(&self) -> String {
        let vals: Vec<u32> = self.bytes
            .chunks(3)
            .map(|bytes| (bytes[0] << 16) | (bytes[1] << 8) | bytes[2])
            .collect();

        let char_table: Vec<char> = vec![
            (b'A'..=b'Z').collect(),
            (b'a'..=b'z').collect(),
            (b'0'..=b'9').collect(),
            vec![b'+', b'/']
        ].iter()
            .flatten()
            .map(|x| *x as char)
            .collect();

        let mut result: Vec<char> = Vec::new();

        for val in vals {
            let chunks = vec![
                ((val & 0xFC0000) >> 18) as u8,
                ((val & 0x03F000) >> 12) as u8,
                ((val & 0x000FC0) >> 6) as u8,
                (val & 0x00003F) as u8
            ];

            let mut chars: Vec<char> = chunks.iter().map(|val| char_table[*val as usize]).collect();
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
