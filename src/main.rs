mod encoding;

fn xor(a: &str, b: &str) -> String {
    let mut xored: Vec<char> = Vec::new();

    let s1 = encoding::hex_to_bytes(a);
    let s2 = encoding::hex_to_bytes(b);

    for (b1, b2) in s1.iter().zip(s2.iter()) {
        xored.push((b1 ^ b2) as u8 as char);
    }

    encoding::bytes_to_hex(xored)
}

fn main() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let base64 = encoding::hex_to_base64(hex);
    println!("{}", base64);
    assert!(base64 == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    let xored = xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965");
    println!("{}", xored);
    assert!(xored == "746865206b696420646f6e277420706c6179")
}
