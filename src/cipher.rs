use colored::*;
use rustls::CipherSuite;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherInfo {
    pub id: u16,
    pub iana_name: String,
    pub openssl_name: Option<String>,
    pub key_exchange: String,
    pub authentication: String,
    pub encryption: String,
    pub bits: u16,
    pub mac: String,
    pub protocol_version: crate::protocol::TlsVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherStrength {
    Null,        // No encryption
    Weak,        // < 128 bits
    Medium,      // 128 bits, but with known weaknesses
    Strong,      // >= 128 bits, no known weaknesses
    Recommended, // Best practice ciphers
}

impl CipherInfo {
    pub fn strength(&self) -> CipherStrength {
        // NULL ciphers
        if self.bits == 0 || self.encryption.contains("NULL") {
            return CipherStrength::Null;
        }

        // Anonymous ciphers
        if self.authentication.contains("anon") || self.authentication == "None" {
            return CipherStrength::Null;
        }

        // Export ciphers or very weak
        if self.bits < 128 || self.encryption.contains("EXPORT") {
            return CipherStrength::Weak;
        }

        // RC4 and 3DES are considered weak
        if self.encryption.contains("RC4") || self.encryption.contains("3DES") {
            return CipherStrength::Weak;
        }

        // CBC mode ciphers in SSLv3 (POODLE)
        if self.protocol_version == crate::protocol::TlsVersion::Ssl3
            && self.encryption.contains("CBC")
        {
            return CipherStrength::Weak;
        }

        // Medium strength - older but not immediately vulnerable
        if self.encryption.contains("CBC")
            || (!self.key_exchange.contains("DHE") && !self.key_exchange.contains("ECDHE"))
        {
            return CipherStrength::Medium;
        }

        // Strong ciphers with PFS and AEAD
        if (self.key_exchange.contains("DHE") || self.key_exchange.contains("ECDHE"))
            && (self.encryption.contains("GCM") || self.encryption.contains("CHACHA20"))
        {
            return CipherStrength::Recommended;
        }

        CipherStrength::Strong
    }

    pub fn format_colored(&self) -> String {
        let strength = self.strength();
        let base = format!(
            "{:<50} {:<10} {:>4} bits",
            self.iana_name,
            self.protocol_version.as_str(),
            self.bits
        );

        match strength {
            CipherStrength::Null => base.on_red().white().to_string(),
            CipherStrength::Weak => base.red().to_string(),
            CipherStrength::Medium => base.yellow().to_string(),
            CipherStrength::Strong => base.normal().to_string(),
            CipherStrength::Recommended => base.green().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuiteResult {
    pub cipher: CipherInfo,
    pub supported: bool,
    pub preferred: bool,
}

use rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES;

/// Known cipher suites from rustls
pub fn get_rustls_cipher_suites() -> Vec<CipherSuite> {
    // Convert SupportedCipherSuite to CipherSuite
    ALL_CIPHER_SUITES.iter().map(|s| s.suite()).collect()
}

/// Convert rustls CipherSuite to our CipherInfo
pub fn rustls_to_cipher_info(suite: CipherSuite) -> CipherInfo {
    // This is a simplified mapping - in a real implementation,
    // we'd have a comprehensive database of cipher suite information
    let suite_name = format!("{:?}", suite);
    // Simplified - we'll use 0 as placeholder for cipher suite ID
    let suite_id = 0u16;

    // Parse cipher suite name to extract components and determine version
    let (kex, auth, enc, bits, mac, version) = parse_cipher_suite_name(&suite_name);

    CipherInfo {
        id: suite_id,
        iana_name: suite_name.to_string(),
        openssl_name: None,
        key_exchange: kex,
        authentication: auth,
        encryption: enc,
        bits,
        mac,
        protocol_version: version,
    }
}

fn parse_cipher_suite_name(
    name: &str,
) -> (
    String,
    String,
    String,
    u16,
    String,
    crate::protocol::TlsVersion,
) {
    use crate::protocol::TlsVersion;

    // Parse common cipher suite patterns
    if name.contains("TLS13") {
        // TLS 1.3 cipher suites
        if name.contains("AES_256_GCM") {
            (
                "TLS1.3".to_string(),
                "TLS1.3".to_string(),
                "AES_256_GCM".to_string(),
                256,
                "SHA384".to_string(),
                TlsVersion::Tls13,
            )
        } else if name.contains("AES_128_GCM") {
            (
                "TLS1.3".to_string(),
                "TLS1.3".to_string(),
                "AES_128_GCM".to_string(),
                128,
                "SHA256".to_string(),
                TlsVersion::Tls13,
            )
        } else if name.contains("CHACHA20_POLY1305") {
            (
                "TLS1.3".to_string(),
                "TLS1.3".to_string(),
                "CHACHA20_POLY1305".to_string(),
                256,
                "SHA256".to_string(),
                TlsVersion::Tls13,
            )
        } else {
            (
                "TLS1.3".to_string(),
                "TLS1.3".to_string(),
                "Unknown".to_string(),
                256,
                "Unknown".to_string(),
                TlsVersion::Tls13,
            )
        }
    } else {
        // TLS 1.2 and below - default to TLS 1.2 since rustls mainly supports TLS 1.2+
        let kex = if name.contains("ECDHE") {
            "ECDHE"
        } else if name.contains("DHE") {
            "DHE"
        } else if name.contains("RSA") {
            "RSA"
        } else {
            "Unknown"
        };

        let auth = if name.contains("ECDSA") {
            "ECDSA"
        } else if name.contains("RSA") {
            "RSA"
        } else {
            "Unknown"
        };

        let (enc, bits) = if name.contains("AES_256_GCM") {
            ("AES_256_GCM", 256)
        } else if name.contains("AES_128_GCM") {
            ("AES_128_GCM", 128)
        } else if name.contains("CHACHA20_POLY1305") {
            ("CHACHA20_POLY1305", 256)
        } else {
            ("Unknown", 0)
        };

        let mac = if name.contains("SHA384") {
            "SHA384"
        } else if name.contains("SHA256") {
            "SHA256"
        } else {
            "Unknown"
        };

        (
            kex.to_string(),
            auth.to_string(),
            enc.to_string(),
            bits,
            mac.to_string(),
            TlsVersion::Tls12,
        )
    }
}

/// Load additional cipher suites not supported by rustls
/// (for detection purposes only)
#[allow(dead_code)]
pub fn load_legacy_cipher_suites() -> Vec<CipherInfo> {
    // This would load cipher definitions for SSL2, SSL3, TLS1.0, TLS1.1
    // and other ciphers not supported by rustls
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::TlsVersion;

    fn create_test_cipher(
        encryption: &str,
        bits: u16,
        auth: &str,
        version: TlsVersion,
    ) -> CipherInfo {
        CipherInfo {
            id: 0x0001,
            iana_name: format!("TLS_TEST_{}", encryption),
            openssl_name: None,
            key_exchange: "DHE".to_string(),
            authentication: auth.to_string(),
            encryption: encryption.to_string(),
            bits,
            mac: "SHA256".to_string(),
            protocol_version: version,
        }
    }

    #[test]
    fn test_cipher_strength_null() {
        let cipher = create_test_cipher("NULL", 0, "RSA", TlsVersion::Tls12);
        assert_eq!(cipher.strength(), CipherStrength::Null);

        let cipher = create_test_cipher("AES_128_GCM", 128, "anon", TlsVersion::Tls12);
        assert_eq!(cipher.strength(), CipherStrength::Null);
    }

    #[test]
    fn test_cipher_strength_weak() {
        let cipher = create_test_cipher("RC4", 128, "RSA", TlsVersion::Tls12);
        assert_eq!(cipher.strength(), CipherStrength::Weak);

        let cipher = create_test_cipher("3DES", 168, "RSA", TlsVersion::Tls12);
        assert_eq!(cipher.strength(), CipherStrength::Weak);

        let cipher = create_test_cipher("AES_64", 64, "RSA", TlsVersion::Tls12);
        assert_eq!(cipher.strength(), CipherStrength::Weak);
    }

    #[test]
    fn test_cipher_strength_ssl3_cbc() {
        let cipher = create_test_cipher("AES_128_CBC", 128, "RSA", TlsVersion::Ssl3);
        assert_eq!(cipher.strength(), CipherStrength::Weak);
    }

    #[test]
    fn test_cipher_strength_recommended() {
        // Must have both PFS (DHE/ECDHE) and AEAD (GCM/CHACHA20)
        let mut cipher = create_test_cipher("AES_256_GCM", 256, "RSA", TlsVersion::Tls12);
        cipher.key_exchange = "ECDHE".to_string();
        assert_eq!(cipher.strength(), CipherStrength::Recommended);

        let mut cipher = create_test_cipher("CHACHA20_POLY1305", 256, "RSA", TlsVersion::Tls12);
        cipher.key_exchange = "DHE".to_string();
        assert_eq!(cipher.strength(), CipherStrength::Recommended);
    }

    #[test]
    fn test_cipher_strength_medium() {
        let cipher = create_test_cipher("AES_128_CBC", 128, "RSA", TlsVersion::Tls12);
        assert_eq!(cipher.strength(), CipherStrength::Medium);
    }

    #[test]
    fn test_get_rustls_cipher_suites() {
        let suites = get_rustls_cipher_suites();
        assert!(!suites.is_empty());
    }
}
