mod encoding;

use regex::Regex;

fn xor(a: &Vec<u32>, b: &Vec<u32>) -> Vec<char> {
    let mut xored: Vec<char> = Vec::new();

    for (b1, b2) in a.iter().zip(b.iter()) {
        xored.push((b1 ^ b2) as u8 as char);
    }

    xored
}

fn english_score(s: &str) -> usize {
    let re = Regex::new(r"[a|e|i|o|u]").unwrap();
    re.find_iter(s).count()
}

fn find_key(cipher: &Vec<u32>) -> Vec<u32> {
    let mut scores: Vec<(u32, usize)> = Vec::new();
    for b in 0..=255 {
        let key = vec![b; cipher.len()];
        let res: String = xor(&cipher, &key).iter().collect();
        scores.push((b, english_score(&res)));
    }

    scores.sort_by(|(_, a), (_, b)| b.cmp(a));
    vec![scores[0].0; cipher.len()]
}

fn main() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = encoding::hex_to_base64(hex);
    println!("{}", base64);
    assert!(base64 == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let xored = encoding::bytes_to_hex(xor(
        &encoding::hex_to_bytes("1c0111001f010100061a024b53535009181c"),
        &encoding::hex_to_bytes("686974207468652062756c6c277320657965")
    ));
    println!("{}", xored);
    assert!(xored == "746865206b696420646f6e277420706c6179");

    let cipher = encoding::hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let key = find_key(&cipher);
    let decrypted: String = xor(&cipher, &key).iter().collect();
    println!("{}", decrypted);
}
