//! Authentication module for HTTP Basic Authentication (RFC 7617).
//!
//! Provides credential storage, verification, and HTTP header parsing for
//! implementing Basic Authentication in WiseGate.

pub mod hash;

use base64::{Engine, engine::general_purpose::STANDARD};

/// A single credential entry (username and password/hash).
#[derive(Debug, Clone)]
pub struct Credential {
    username: String,
    password: String,
}

impl Credential {
    /// Creates a new credential from username and password/hash.
    pub fn new(username: String, password: String) -> Self {
        Self { username, password }
    }

    /// Parses a credential string in the format "username:password".
    ///
    /// # Errors
    ///
    /// Returns `None` if the string doesn't contain a colon or has an empty username.
    pub fn parse(value: &str) -> Option<Self> {
        let (user, pass) = value.split_once(':')?;
        if user.is_empty() {
            return None;
        }
        Some(Self::new(user.to_string(), pass.to_string()))
    }

    /// Returns the username.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password/hash.
    pub fn password(&self) -> &str {
        &self.password
    }
}

/// Stores credentials for authentication.
#[derive(Debug, Clone)]
pub struct Credentials {
    entries: Vec<Credential>,
}

impl Credentials {
    /// Creates a new empty credentials store.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Creates credentials from a slice of credential entries.
    pub fn from_entries(entries: Vec<Credential>) -> Self {
        Self { entries }
    }

    /// Returns true if no credentials are stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of stored credentials.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns an iterator over the credentials.
    pub fn iter(&self) -> impl Iterator<Item = &Credential> {
        self.entries.iter()
    }

    /// Verifies credentials from an HTTP Authorization header.
    ///
    /// Expects the header value in the format `Basic {base64-encoded-credentials}`
    /// per RFC 7617.
    pub fn verify(&self, auth_header: &str) -> bool {
        let Some(encoded) = auth_header.strip_prefix("Basic ") else {
            return false;
        };

        let Ok(decoded) = STANDARD.decode(encoded.trim()) else {
            return false;
        };

        let Ok(decoded_str) = String::from_utf8(decoded) else {
            return false;
        };

        // RFC 7617: user-id cannot contain colons, password may contain colons
        let Some((user, password)) = decoded_str.split_once(':') else {
            return false;
        };

        self.check(user, password)
    }

    /// Checks if the given username and password match any stored credential.
    /// Uses constant-time comparison to prevent timing attacks.
    fn check(&self, username: &str, password: &str) -> bool {
        let mut found = false;
        for cred in &self.entries {
            // Use constant-time comparison for username to prevent enumeration
            let user_match = hash::constant_time_eq(cred.username.as_bytes(), username.as_bytes());
            // Always verify password to prevent timing leaks
            let pass_match = hash::verify(password, &cred.password);
            if user_match && pass_match {
                found = true;
            }
        }
        found
    }
}

impl Default for Credentials {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if the request has valid authentication.
///
/// Returns `true` if authentication is successful or not required.
/// Returns `false` if authentication is required but failed.
///
/// # Arguments
///
/// * `auth_header` - The value of the Authorization header, if present.
/// * `credentials` - The credentials to check against.
pub fn check_basic_auth(auth_header: Option<&str>, credentials: &Credentials) -> bool {
    if credentials.is_empty() {
        // No credentials configured, authentication not required
        return true;
    }

    match auth_header {
        Some(header) => credentials.verify(header),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_parse_valid() {
        let cred = Credential::parse("admin:secret").unwrap();
        assert_eq!(cred.username(), "admin");
        assert_eq!(cred.password(), "secret");
    }

    #[test]
    fn test_credential_parse_with_colon_in_password() {
        let cred = Credential::parse("admin:sec:ret").unwrap();
        assert_eq!(cred.username(), "admin");
        assert_eq!(cred.password(), "sec:ret");
    }

    #[test]
    fn test_credential_parse_no_colon() {
        assert!(Credential::parse("invalid").is_none());
    }

    #[test]
    fn test_credential_parse_empty_user() {
        assert!(Credential::parse(":password").is_none());
    }

    #[test]
    fn test_credentials_empty() {
        let creds = Credentials::new();
        assert!(creds.is_empty());
        assert_eq!(creds.len(), 0);
    }

    #[test]
    fn test_credentials_from_entries() {
        let entries = vec![
            Credential::new("admin".to_string(), "secret".to_string()),
            Credential::new("user".to_string(), "pass".to_string()),
        ];
        let creds = Credentials::from_entries(entries);
        assert!(!creds.is_empty());
        assert_eq!(creds.len(), 2);
    }

    #[test]
    fn test_verify_plain_text() {
        let creds = Credentials::from_entries(vec![Credential::new(
            "admin".to_string(),
            "secret".to_string(),
        )]);

        let header = format!("Basic {}", STANDARD.encode("admin:secret"));
        assert!(creds.verify(&header));
    }

    #[test]
    fn test_verify_wrong_password() {
        let creds = Credentials::from_entries(vec![Credential::new(
            "admin".to_string(),
            "secret".to_string(),
        )]);

        let header = format!("Basic {}", STANDARD.encode("admin:wrong"));
        assert!(!creds.verify(&header));
    }

    #[test]
    fn test_verify_wrong_user() {
        let creds = Credentials::from_entries(vec![Credential::new(
            "admin".to_string(),
            "secret".to_string(),
        )]);

        let header = format!("Basic {}", STANDARD.encode("wrong:secret"));
        assert!(!creds.verify(&header));
    }

    #[test]
    fn test_verify_bcrypt() {
        // bcrypt hash for "password"
        let hash = "$2y$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe";
        let creds =
            Credentials::from_entries(vec![Credential::new("user".to_string(), hash.to_string())]);

        let header = format!("Basic {}", STANDARD.encode("user:password"));
        assert!(creds.verify(&header));
    }

    #[test]
    fn test_verify_sha1() {
        // SHA1 hash for "password"
        let hash = "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=";
        let creds =
            Credentials::from_entries(vec![Credential::new("user".to_string(), hash.to_string())]);

        let header = format!("Basic {}", STANDARD.encode("user:password"));
        assert!(creds.verify(&header));
    }

    #[test]
    fn test_verify_apr1() {
        // APR1 hash for "password"
        let hash = "$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
        let creds =
            Credentials::from_entries(vec![Credential::new("user".to_string(), hash.to_string())]);

        let header = format!("Basic {}", STANDARD.encode("user:password"));
        assert!(creds.verify(&header));
    }

    #[test]
    fn test_verify_multiple_credentials() {
        let creds = Credentials::from_entries(vec![
            Credential::new("admin".to_string(), "admin123".to_string()),
            Credential::new("user1".to_string(), "pass1".to_string()),
            Credential::new("user2".to_string(), "pass2".to_string()),
        ]);

        assert!(creds.verify(&format!("Basic {}", STANDARD.encode("admin:admin123"))));
        assert!(creds.verify(&format!("Basic {}", STANDARD.encode("user1:pass1"))));
        assert!(creds.verify(&format!("Basic {}", STANDARD.encode("user2:pass2"))));
        assert!(!creds.verify(&format!("Basic {}", STANDARD.encode("unknown:pass"))));
    }

    #[test]
    fn test_verify_invalid_base64() {
        let creds = Credentials::from_entries(vec![Credential::new(
            "admin".to_string(),
            "secret".to_string(),
        )]);
        assert!(!creds.verify("Basic not-valid-base64!!!"));
    }

    #[test]
    fn test_verify_non_basic_auth() {
        let creds = Credentials::from_entries(vec![Credential::new(
            "admin".to_string(),
            "secret".to_string(),
        )]);
        assert!(!creds.verify("Bearer some-token"));
    }

    #[test]
    fn test_verify_missing_colon_in_decoded() {
        let creds = Credentials::from_entries(vec![Credential::new(
            "admin".to_string(),
            "secret".to_string(),
        )]);
        let header = format!("Basic {}", STANDARD.encode("no-colon-here"));
        assert!(!creds.verify(&header));
    }

    #[test]
    fn test_check_basic_auth_no_credentials() {
        let creds = Credentials::new();
        // No credentials = authentication not required
        assert!(check_basic_auth(None, &creds));
        assert!(check_basic_auth(Some("Basic anything"), &creds));
    }

    #[test]
    fn test_check_basic_auth_with_credentials() {
        let creds = Credentials::from_entries(vec![Credential::new(
            "admin".to_string(),
            "secret".to_string(),
        )]);

        // No header = fail
        assert!(!check_basic_auth(None, &creds));

        // Valid header = success
        let valid_header = format!("Basic {}", STANDARD.encode("admin:secret"));
        assert!(check_basic_auth(Some(&valid_header), &creds));

        // Invalid header = fail
        let invalid_header = format!("Basic {}", STANDARD.encode("admin:wrong"));
        assert!(!check_basic_auth(Some(&invalid_header), &creds));
    }
}
