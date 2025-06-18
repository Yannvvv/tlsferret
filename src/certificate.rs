use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;
use der_parser::oid::Oid;
use sha2::{Sha256, Digest};
use sha1::Sha1;

/// Convert ASN1Time to chrono::DateTime<Utc>
fn offset_to_chrono(asn1_time: x509_parser::time::ASN1Time) -> DateTime<Utc> {
    let offset_dt = asn1_time.to_datetime();
    match DateTime::from_timestamp(offset_dt.unix_timestamp(), 0) {
        Some(dt) => dt,
        None => Utc::now(), // Fallback to current time if conversion fails
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_size: usize,
    pub ecc_curve_name: Option<String>,
    pub ecc_key_strength: Option<u16>,
    pub san: Vec<String>,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub days_until_expiry: i64,
    pub fingerprint_sha256: String,
    pub fingerprint_sha1: String,
    pub weak_signature: bool,
    pub weak_key: bool,
}

impl CertificateInfo {
    pub fn from_der(der_data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let (_, cert) = X509Certificate::from_der(der_data)?;
        
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();
        let serial = cert.raw_serial_as_string();
        
        let not_before = offset_to_chrono(cert.validity().not_before);
        let not_after = offset_to_chrono(cert.validity().not_after);
        
        let sig_alg = oid_to_algorithm_name(&cert.signature_algorithm.algorithm);
        let is_self_signed = cert.subject() == cert.issuer();
        
        let now = Utc::now();
        let is_expired = now > not_after;
        let days_until_expiry = (not_after - now).num_days();
        
        // Extract public key info
        let pki = cert.public_key();
        let alg_name = oid_to_algorithm_name(&pki.algorithm.algorithm);
        let key_size = estimate_key_size(&pki);
        let (pub_key_alg, pub_key_size) = (alg_name, key_size);
        
        // Extract ECC curve information
        let (ecc_curve_name, ecc_key_strength) = extract_ecc_info(&pki);
        
        // Extract SANs
        let san = extract_san_names(&cert);
        
        // Calculate fingerprints
        let mut hasher_sha256 = Sha256::new();
        hasher_sha256.update(&der_data);
        let fingerprint_sha256 = hex::encode(hasher_sha256.finalize());
        
        let mut hasher_sha1 = Sha1::new();
        hasher_sha1.update(&der_data);
        let fingerprint_sha1 = hex::encode(hasher_sha1.finalize());
        
        // Check for weak crypto
        let weak_signature = is_weak_signature(&sig_alg);
        let weak_key = is_weak_key(&pub_key_alg, pub_key_size);
        
        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number: serial,
            not_before,
            not_after,
            signature_algorithm: sig_alg,
            public_key_algorithm: pub_key_alg,
            public_key_size: pub_key_size,
            ecc_curve_name,
            ecc_key_strength,
            san,
            is_self_signed,
            is_expired,
            days_until_expiry,
            fingerprint_sha256,
            fingerprint_sha1,
            weak_signature,
            weak_key,
        })
    }
    
    pub fn validation_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        
        if self.is_expired {
            issues.push("Certificate has expired".to_string());
        } else if self.days_until_expiry < 30 {
            issues.push(format!("Certificate expires in {} days", self.days_until_expiry));
        }
        
        if self.weak_signature {
            issues.push(format!("Weak signature algorithm: {}", self.signature_algorithm));
        }
        
        if self.weak_key {
            issues.push(format!(
                "Weak key: {} {} bits", 
                self.public_key_algorithm, 
                self.public_key_size
            ));
        }
        
        if self.is_self_signed {
            issues.push("Self-signed certificate".to_string());
        }
        
        issues
    }
}

fn oid_to_algorithm_name(oid: &Oid) -> String {
    let oid_str = oid.to_id_string();
    match oid_str.as_str() {
        "1.2.840.113549.1.1.5" => "SHA1withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.10045.4.3.2" => "SHA256withECDSA",
        "1.2.840.10045.4.3.3" => "SHA384withECDSA",
        "1.3.101.112" => "Ed25519",
        "1.2.840.113549.1.1.1" => "RSA",
        "1.2.840.10045.2.1" => "EC",
        _ => &oid_str,
    }.to_string()
}

fn estimate_key_size(pki: &SubjectPublicKeyInfo) -> usize {
    let oid_str = pki.algorithm.algorithm.to_id_string();
    match oid_str.as_str() {
        "1.2.840.113549.1.1.1" => {
            // RSA key - estimate from key data length
            // This is a rough approximation
            let data_len = pki.subject_public_key.data.len();
            if data_len > 400 {
                4096
            } else if data_len > 300 {
                2048
            } else if data_len > 200 {
                1024
            } else {
                data_len * 8
            }
        }
        "1.2.840.10045.2.1" => {
            // EC keys - estimate based on key data length
            let data_len = pki.subject_public_key.data.len();
            match data_len {
                65 => 256,   // P-256
                97 => 384,   // P-384
                133 => 521,  // P-521
                _ => data_len * 4,
            }
        }
        _ => pki.subject_public_key.data.len() * 8,
    }
}

fn extract_san_names(cert: &X509Certificate) -> Vec<String> {
    let mut names = Vec::new();
    
    // Try to find Subject Alternative Name extension
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == "2.5.29.17" { // SAN OID
            // Parse the extension value as SubjectAlternativeName
            use x509_parser::extensions::ParsedExtension;
            
            if let ParsedExtension::SubjectAlternativeName(san_ext) = ext.parsed_extension() {
                for general_name in &san_ext.general_names {
                    use x509_parser::extensions::GeneralName;
                    match general_name {
                        GeneralName::DNSName(dns) => {
                            names.push(dns.to_string());
                        }
                        GeneralName::IPAddress(ip) => {
                            // Convert IP bytes to string
                            match ip.len() {
                                4 => {
                                    // IPv4
                                    let addr = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                                    names.push(addr);
                                }
                                16 => {
                                    // IPv6
                                    let mut segments = Vec::new();
                                    for i in (0..16).step_by(2) {
                                        segments.push(format!("{:x}{:x}", ip[i], ip[i+1]));
                                    }
                                    names.push(segments.join(":"));
                                }
                                _ => {
                                    names.push("Invalid IP address".to_string());
                                }
                            }
                        }
                        GeneralName::RFC822Name(email) => {
                            names.push(format!("Email: {}", email));
                        }
                        GeneralName::URI(uri) => {
                            names.push(format!("URI: {}", uri));
                        }
                        _ => {
                            // Other types not commonly used in web certificates
                            continue;
                        }
                    }
                }
            }
        }
    }
    
    // If no SANs found, return empty vector (not an error)
    names
}

/// Extract ECC curve information from public key
fn extract_ecc_info(pki: &SubjectPublicKeyInfo) -> (Option<String>, Option<u16>) {
    let oid_str = pki.algorithm.algorithm.to_id_string();
    
    if oid_str == "1.2.840.10045.2.1" { // EC public key OID
        // Try to determine curve from key size or parameters
        let key_size = pki.subject_public_key.data.len();
        
        // Common ECC curves and their approximate sizes
        let (curve_name, strength) = match key_size {
            65 => ("secp256r1", 256),   // P-256
            97 => ("secp384r1", 384),   // P-384
            133 => ("secp521r1", 521),  // P-521
            _ => ("Unknown ECC", key_size as u16 * 4), // Rough estimate
        };
        
        (Some(curve_name.to_string()), Some(strength))
    } else {
        // Not an ECC key
        (None, None)
    }
}

fn is_weak_signature(algorithm: &str) -> bool {
    algorithm.contains("SHA1") || algorithm.contains("MD5")
}

fn is_weak_key(algorithm: &str, size: usize) -> bool {
    match algorithm {
        alg if alg.contains("RSA") => size < 2048,
        alg if alg.contains("EC") => size < 224,
        _ => false,
    }
}

/// Parse certificate chain from TLS handshake
#[allow(dead_code)]
pub fn parse_certificate_chain(chain_data: &[u8]) -> Result<Vec<CertificateInfo>, Box<dyn std::error::Error>> {
    let mut certificates = Vec::new();
    let mut data = chain_data;
    
    while !data.is_empty() {
        match X509Certificate::from_der(data) {
            Ok((remaining, _cert)) => {
                if let Ok(cert_info) = CertificateInfo::from_der(&data[..data.len() - remaining.len()]) {
                    certificates.push(cert_info);
                }
                data = remaining;
            }
            Err(_) => break,
        }
    }
    
    Ok(certificates)
}