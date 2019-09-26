mod encoding;

use regex::Regex;

fn english_score(s: &str) -> usize {
    let re = Regex::new(r"[a|e|i|o|u]").unwrap();
    re.find_iter(s).count()
}

fn find_key(cipher: &encoding::ByteArray) -> encoding::ByteArray {
    let mut scores: Vec<(u32, usize)> = Vec::new();

    for b in 0..=255 {
        let key = encoding::ByteArray::from_bytes(vec![b; cipher.len()]);
        let res = cipher.xor(&key).string();
        scores.push((b, english_score(&res)));
    }

    scores.sort_by(|(_, a), (_, b)| b.cmp(a));
    encoding::ByteArray::from_bytes(vec![scores[0].0; cipher.len()])
}

fn main() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let byte_array = encoding::ByteArray::from_hex(hex);
    let base64 = byte_array.base64();
    println!("{}", base64);
    assert!(base64 == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let a = encoding::ByteArray::from_hex("1c0111001f010100061a024b53535009181c");
    let b = encoding::ByteArray::from_hex("686974207468652062756c6c277320657965");
    let xored = a.xor(&b).hex();
    println!("{}", xored);
    assert!(xored == "746865206b696420646f6e277420706c6179");

    let cipher = encoding::ByteArray::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let key = find_key(&cipher);
    let decrypted = cipher.xor(&key).string();
    println!("{}", decrypted);
}
