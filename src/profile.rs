use crate::aes;
use crate::encoding::ByteArray;

fn profile_for(email: &str) -> String {
    format!("email={}&uid=123&role=user", email.replace("&", "").replace("=", ""))
}

fn encrypt_profile(profile: &str, key: &[u8]) -> Result<ByteArray, aes::Error> {
    let data = ByteArray::from_string(profile);
    aes::encrypt_ecb(&data, &key)
}

fn decrypt_profile(encrypted: &ByteArray, key: &[u8]) -> Result<ByteArray, aes::Error> {
    aes::decrypt_ecb(encrypted, &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_for() {
        let result = profile_for("foo@bar.com");
        assert_eq!(result, "email=foo@bar.com&uid=123&role=user");

        let result = profile_for("foo@bar.com&role=admin");
        assert_eq!(result, "email=foo@bar.comroleadmin&uid=123&role=user");
    }

    #[test]
    fn test_encrypt_decrypt_profile() {
        let profile = profile_for("foo@bar.com");

        let key = aes::random_key();
        let encrypted = encrypt_profile(&profile, &key).unwrap();
        let decrypted = decrypt_profile(&encrypted, &key).unwrap();
        assert_eq!(decrypted.string(), profile);
    }

    #[test]
    fn test_admin_profile() {
        let key = aes::random_key();

        // results in padded "user" being the 3rd block
        let profile1 = profile_for("xxxxxxxxxxxx");
        let encrypted_profile1 = encrypt_profile(&profile1, &key).unwrap().bytes();

        // results in padded "admin" being the 2nd block
        let profile2 = profile_for("xxxxxxxxxxadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B");
        let mut encrypted_profile2 = encrypt_profile(&profile2, &key).unwrap().bytes();

        let mut ciphertext = encrypted_profile1[0..32].to_vec();
        ciphertext.append(&mut encrypted_profile2[16..32].to_vec());

        let encrypted_admin = ByteArray::from_bytes(ciphertext);
        let decrypted_admin = decrypt_profile(&encrypted_admin, &key).unwrap();
        assert_eq!(decrypted_admin.string(), "email=xxxxxxxxxxxx&uid=123&role=admin");
    }
}
