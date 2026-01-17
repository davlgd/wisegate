//! Native password hash verification for Apache htpasswd formats.
//!
//! Supported formats:
//! - bcrypt ($2y$, $2a$, $2b$)
//! - APR1 MD5 ($apr1$)
//! - SHA1 ({SHA})
//! - Plain text (fallback)

use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};
use sha1::Sha1;

/// Verifies a password against a stored hash.
/// Automatically detects the hash format and uses the appropriate algorithm.
pub fn verify(password: &str, hash: &str) -> bool {
    if hash.starts_with("$2y$") || hash.starts_with("$2a$") || hash.starts_with("$2b$") {
        verify_bcrypt(password, hash)
    } else if hash.starts_with("$apr1$") {
        verify_apr1(password, hash)
    } else if hash.starts_with("{SHA}") {
        verify_sha1(password, hash)
    } else {
        // Plain text comparison using constant-time comparison
        constant_time_eq(password.as_bytes(), hash.as_bytes())
    }
}

/// Constant-time byte comparison to prevent timing attacks.
/// Does not leak length information through timing.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_eq = a.len() == b.len();
    let max_len = a.len().max(b.len());
    let mut result = 0u8;

    for i in 0..max_len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        result |= x ^ y;
    }

    len_eq && result == 0
}

/// Verifies a password against a bcrypt hash.
fn verify_bcrypt(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// Verifies a password against a SHA1 hash ({SHA} prefix, Base64-encoded).
fn verify_sha1(password: &str, hash: &str) -> bool {
    let Some(encoded) = hash.strip_prefix("{SHA}") else {
        return false;
    };

    let Ok(stored_digest) = STANDARD.decode(encoded) else {
        return false;
    };

    let computed_digest = Sha1::digest(password.as_bytes());
    constant_time_eq(computed_digest.as_slice(), &stored_digest)
}

/// Verifies a password against an APR1 MD5 hash ($apr1$ prefix).
/// Implements Apache's modified MD5-crypt algorithm.
fn verify_apr1(password: &str, hash: &str) -> bool {
    let Some(rest) = hash.strip_prefix("$apr1$") else {
        return false;
    };

    let Some((salt, _)) = rest.split_once('$') else {
        return false;
    };

    let computed = apr1_hash(password, salt);
    constant_time_eq(computed.as_bytes(), hash.as_bytes())
}

/// Computes an APR1 MD5 hash for a password with the given salt.
/// Based on Apache's apr_md5.c implementation.
fn apr1_hash(password: &str, salt: &str) -> String {
    let password = password.as_bytes();
    let salt = salt.as_bytes();

    // Initial hash: password + $apr1$ + salt
    let mut ctx = Md5::new();
    ctx.update(password);
    ctx.update(b"$apr1$");
    ctx.update(salt);

    // Alternate hash: password + salt + password
    let mut ctx1 = Md5::new();
    ctx1.update(password);
    ctx1.update(salt);
    ctx1.update(password);
    let fin = ctx1.finalize();

    // Add alternate hash bytes based on password length
    let mut pl = password.len();
    let mut i = 0;
    while pl > 0 {
        let len = if pl > 16 { 16 } else { pl };
        ctx.update(&fin[i..i + len]);
        pl -= len;
        i += len;
        if i >= 16 {
            i = 0;
        }
    }

    // Add null or first password char based on password length bits
    let mut pl = password.len();
    while pl > 0 {
        if pl & 1 != 0 {
            ctx.update([0u8]);
        } else {
            ctx.update(&password[0..1]);
        }
        pl >>= 1;
    }

    let mut fin = ctx.finalize();

    // 1000 rounds of MD5
    for i in 0..1000 {
        let mut ctx1 = Md5::new();

        if i & 1 != 0 {
            ctx1.update(password);
        } else {
            ctx1.update(fin.as_slice());
        }

        if i % 3 != 0 {
            ctx1.update(salt);
        }

        if i % 7 != 0 {
            ctx1.update(password);
        }

        if i & 1 != 0 {
            ctx1.update(fin.as_slice());
        } else {
            ctx1.update(password);
        }

        fin = ctx1.finalize();
    }

    // Convert GenericArray to fixed-size array for encoding
    let fin_arr: [u8; 16] = fin.into();
    let encoded = apr1_encode(&fin_arr);
    format!(
        "$apr1${salt}${encoded}",
        salt = std::str::from_utf8(salt).unwrap_or("")
    )
}

/// Custom Base64 encoding for APR1 MD5 hashes.
/// Uses a different alphabet and byte ordering than standard Base64.
fn apr1_encode(digest: &[u8; 16]) -> String {
    const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    let mut result = String::with_capacity(22);

    // APR1 uses a specific byte ordering for the final encoding
    let encode_triple = |a: u8, b: u8, c: u8| -> [char; 4] {
        let v = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
        [
            ITOA64[(v & 0x3f) as usize] as char,
            ITOA64[((v >> 6) & 0x3f) as usize] as char,
            ITOA64[((v >> 12) & 0x3f) as usize] as char,
            ITOA64[((v >> 18) & 0x3f) as usize] as char,
        ]
    };

    // Encode in the specific APR1 byte order
    for chars in encode_triple(digest[0], digest[6], digest[12]) {
        result.push(chars);
    }
    for chars in encode_triple(digest[1], digest[7], digest[13]) {
        result.push(chars);
    }
    for chars in encode_triple(digest[2], digest[8], digest[14]) {
        result.push(chars);
    }
    for chars in encode_triple(digest[3], digest[9], digest[15]) {
        result.push(chars);
    }
    for chars in encode_triple(digest[4], digest[10], digest[5]) {
        result.push(chars);
    }

    // Last byte only needs 2 characters
    let v = u32::from(digest[11]);
    result.push(ITOA64[(v & 0x3f) as usize] as char);
    result.push(ITOA64[((v >> 6) & 0x3f) as usize] as char);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_plain_text() {
        assert!(verify("secret", "secret"));
        assert!(!verify("secret", "wrong"));
    }

    #[test]
    fn test_verify_sha1_password() {
        // "password" hashed with SHA1: echo -n "password" | openssl dgst -sha1 -binary | base64
        let hash = "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=";
        assert!(verify("password", hash));
        assert!(!verify("wrong", hash));
    }

    #[test]
    fn test_verify_bcrypt_password() {
        // "password" hashed with bcrypt (cost 5)
        let hash = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
        assert!(verify("password", hash));
        assert!(!verify("wrong", hash));
    }

    #[test]
    fn test_verify_apr1_password() {
        // "password" hashed with apr1: htpasswd -nbm user password
        let hash = "$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
        assert!(verify("password", hash));
        assert!(!verify("wrong", hash));
    }

    #[test]
    fn test_apr1_known_hash() {
        // Test against a known APR1 hash
        let computed = apr1_hash("password", "lZL6V/ci");
        assert_eq!(computed, "$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00");
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
