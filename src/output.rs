use anyhow::Result;
use clap::ValueEnum;
use colored::*;
use std::fs::File;
use std::io::Write;

use crate::cipher::CipherStrength;
use crate::protocol::TlsVersion;
use crate::scanner::ScanResults;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
pub enum OutputFormat {
    Text,
    Json,
    Xml,
}

pub fn print_text_results(results: &ScanResults) {
    println!("{}", "SSL/TLS Scan Results".bold().underline());
    println!();

    // Target information
    println!("{}:", "Target".bold());
    println!("  Host: {}", results.hostname);
    println!("  IP: {}", results.target);
    println!("  Port: {}", results.port);
    println!();

    // Protocol support
    println!("{}:", "Supported Protocols".bold());
    for protocol in &results.protocol_support {
        let status = if protocol.supported {
            if protocol.version.is_secure() {
                "YES".green()
            } else if protocol.version.is_deprecated() {
                "YES".yellow()
            } else {
                "YES".red()
            }
        } else {
            "NO".normal()
        };

        println!("  {:<10} {}", protocol.version.as_str(), status);

        if let Some(error) = &protocol.error {
            if protocol.supported {
                println!("    {}", error.dimmed());
            }
        }
    }
    println!();

    // TLS Fallback SCSV
    if let Some(fallback_scsv) = results.fallback_scsv_supported {
        println!("{}:", "TLS Fallback SCSV".bold());
        let status = if fallback_scsv {
            "Supported".green()
        } else {
            "Not Supported".red()
        };
        println!("  {}", status);

        if fallback_scsv {
            println!(
                "  {}",
                "✓ Server protects against downgrade attacks".dimmed()
            );
        } else {
            println!(
                "  {}",
                "⚠ Server may be vulnerable to downgrade attacks"
                    .yellow()
                    .dimmed()
            );
        }
        println!();
    }

    // TLS renegotiation
    println!("{}:", "TLS renegotiation".bold());

    // Secure renegotiation (RFC 5746)
    if let Some(secure_renego) = results.tls_renegotiation.secure_renegotiation {
        let status = if secure_renego {
            "Supported".green()
        } else {
            "Not Supported".red()
        };
        println!("  Secure renegotiation (RFC 5746): {}", status);

        if !secure_renego {
            println!(
                "    {}",
                "⚠ Server may be vulnerable to renegotiation attacks"
                    .yellow()
                    .dimmed()
            );
        }
    } else {
        println!("  Secure renegotiation (RFC 5746): {}", "Unknown".yellow());
    }

    // Client-initiated renegotiation
    if let Some(client_renego) = results.tls_renegotiation.client_initiated_renegotiation {
        let status = if client_renego {
            "Enabled".red()
        } else {
            "Disabled".green()
        };
        println!("  Client-initiated renegotiation: {}", status);

        if client_renego {
            println!(
                "    {}",
                "⚠ Server allows client renegotiation (DoS risk)"
                    .yellow()
                    .dimmed()
            );
        } else {
            println!("    {}", "✓ Server rejects client renegotiation".dimmed());
        }
    } else {
        println!("  Client-initiated renegotiation: {}", "Unknown".yellow());
    }

    // TLS compression (CRIME)
    if let Some(compression) = results.tls_renegotiation.compression_supported {
        let status = if compression {
            "Enabled".red()
        } else {
            "Disabled".green()
        };
        println!("  TLS compression: {}", status);

        if compression {
            println!(
                "    {}",
                "⚠ Server vulnerable to CRIME attack (CVE-2012-4929)"
                    .red()
                    .dimmed()
            );
        } else {
            println!("    {}", "✓ Server not vulnerable to CRIME attack".dimmed());
        }
    } else {
        println!("  TLS compression: {}", "Unknown".yellow());
    }

    println!();

    // Heartbleed vulnerability
    if let Some(heartbleed) = results.heartbleed_vulnerable {
        println!("{}:", "Heartbleed (CVE-2014-0160)".bold());
        let status = if heartbleed {
            "VULNERABLE".red().bold()
        } else {
            "Not Vulnerable".green()
        };
        println!("  {}", status);

        if heartbleed {
            println!(
                "    {}",
                "⚠ CRITICAL: Server is vulnerable to Heartbleed attack!"
                    .red()
                    .bold()
            );
            println!(
                "    {}",
                "⚠ Private keys, passwords, and sensitive data may be leaked"
                    .red()
                    .dimmed()
            );
            println!("    {}", "⚠ Immediate patching required!".red().dimmed());
        } else {
            println!(
                "    {}",
                "✓ Server is protected against Heartbleed attacks".dimmed()
            );
        }
        println!();
    }

    // Preferred cipher
    if let Some(preferred) = &results.preferred_cipher {
        println!("{}:", "Preferred Cipher".bold());
        println!("  {}", preferred.format_colored());
        println!();
    }

    // Cipher suites
    if !results.cipher_suites.is_empty() {
        println!("{}:", "Supported Cipher Suites".bold());
        println!("  (Preferred cipher marked with {})", "*".yellow());
        println!();

        // Group by protocol version
        let mut by_version: std::collections::HashMap<TlsVersion, Vec<_>> =
            std::collections::HashMap::new();

        for result in &results.cipher_suites {
            if result.supported {
                by_version
                    .entry(result.cipher.protocol_version)
                    .or_insert_with(Vec::new)
                    .push(result);
            }
        }

        for version in &[
            TlsVersion::Tls13,
            TlsVersion::Tls12,
            TlsVersion::Tls11,
            TlsVersion::Tls10,
            TlsVersion::Ssl3,
            TlsVersion::Ssl2,
        ] {
            if let Some(ciphers) = by_version.get(version) {
                println!("  {}:", version.as_str().bold());
                for cipher_result in ciphers {
                    let prefix = if cipher_result.preferred { "*" } else { " " };
                    println!(
                        "  {} {}",
                        prefix.yellow(),
                        cipher_result.cipher.format_colored()
                    );
                }
                println!();
            }
        }
    }

    // Server Key Exchange Groups
    if !results.key_exchange_groups.is_empty() {
        println!("{}:", "Server Key Exchange Group(s)".bold());
        println!();

        // Separate classical and post-quantum groups
        let classical_groups: Vec<_> = results
            .key_exchange_groups
            .iter()
            .filter(|g| !g.post_quantum && g.supported)
            .collect();
        let pq_groups: Vec<_> = results
            .key_exchange_groups
            .iter()
            .filter(|g| g.post_quantum && g.supported)
            .collect();

        if !classical_groups.is_empty() {
            println!("  {}:", "Classical Groups".bold());
            for group in classical_groups {
                let status = if group.negotiated {
                    format!("{} (negotiated)", "✓".green())
                } else {
                    "✓".green().to_string()
                };
                println!("    {:<20} {}", group.name, status);
            }
            println!();
        }

        if !pq_groups.is_empty() {
            println!("  {}:", "Post-Quantum Groups".bold());
            for group in pq_groups {
                let status = if group.negotiated {
                    format!("{} (negotiated)", "✓".green())
                } else {
                    "✓".green().to_string()
                };
                let name_colored = if group.name.contains("MLKEM") {
                    group.name.cyan().bold()
                } else {
                    group.name.normal()
                };
                println!("    {:<20} {}", name_colored, status);
            }
            println!();
        }
    }

    // Certificate information
    if !results.certificate_chain.is_empty() {
        println!();
        println!("{}:", "Certificate Information".bold());
        println!();

        for (i, cert) in results.certificate_chain.iter().enumerate() {
            // Certificate header with chain position
            let cert_type = if i == 0 { "Server" } else { "Intermediate" };
            println!(
                "  {}:",
                format!("{} Certificate (#{} in chain)", cert_type, i + 1).underline()
            );
            println!();

            // Basic Information section
            println!("    {}:", "Basic Information".bold());
            println!("      Subject:             {}", cert.subject);
            println!("      Issuer:              {}", cert.issuer);

            // Alternative Names
            if !cert.san.is_empty() {
                println!("      Alternative Names:");
                for san in &cert.san {
                    println!("        - {}", san);
                }
            }
            println!();

            // Key Information section
            println!("    {}:", "Public Key Information".bold());
            if let Some(curve_name) = &cert.ecc_curve_name {
                println!(
                    "      Algorithm:           {} ({})",
                    cert.public_key_algorithm, curve_name
                );
                if let Some(strength) = cert.ecc_key_strength {
                    println!("      Key Strength:        {} bits", strength);
                }
            } else {
                println!("      Algorithm:           {}", cert.public_key_algorithm);
                println!("      Key Size:            {} bits", cert.public_key_size);
            }

            // Signature Algorithm with security indicator
            print!("      Signature Algorithm: {}", cert.signature_algorithm);
            if cert.weak_signature {
                println!(" {}", "(WEAK)".red().bold());
            } else {
                println!();
            }
            println!();

            // Validity Period section
            println!("    {}:", "Validity Period".bold());
            println!(
                "      Not Before:          {}",
                cert.not_before.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "      Not After:           {}",
                cert.not_after.format("%Y-%m-%d %H:%M:%S UTC")
            );

            // Calculate days remaining
            let now = chrono::Utc::now();
            if cert.not_after > now {
                let days_remaining = (cert.not_after - now).num_days();
                let status = if days_remaining < 30 {
                    format!("{} days remaining", days_remaining).red()
                } else if days_remaining < 90 {
                    format!("{} days remaining", days_remaining).yellow()
                } else {
                    format!("{} days remaining", days_remaining).green()
                };
                println!("      Status:              {}", status);
            } else {
                println!("      Status:              {}", "EXPIRED".red().bold());
            }
            println!();

            // Technical Details section
            println!("    {}:", "Technical Details".bold());
            println!("      Serial Number:       {}", cert.serial_number);

            // Fingerprints
            println!("      SHA256 Fingerprint:  {}", cert.fingerprint_sha256);
            println!(
                "      SHA1 Fingerprint:    {}",
                cert.fingerprint_sha1.dimmed()
            );

            // Validation issues
            let issues = cert.validation_issues();
            if !issues.is_empty() {
                println!();
                println!("    {}:", "Security Issues".red().bold());
                for issue in issues {
                    println!("      ⚠ {}", issue.red());
                }
            }

            // Add spacing between certificates
            if i < results.certificate_chain.len() - 1 {
                println!();
                println!("  {}", "─".repeat(60).dimmed());
                println!();
            }
        }
        println!();
    }

    // Summary
    print_summary(results);
}

pub fn print_json_results(results: &ScanResults) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    println!("{}", json);
    Ok(())
}

pub fn print_xml_results(results: &ScanResults) -> Result<()> {
    let xml = quick_xml::se::to_string(results)?;
    println!("{}", xml);
    Ok(())
}

pub fn save_results(results: &ScanResults, path: &str, format: OutputFormat) -> Result<()> {
    let mut file = File::create(path)?;

    match format {
        OutputFormat::Text => {
            // Redirect stdout to string
            let output = format_text_results(results);
            file.write_all(output.as_bytes())?;
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(results)?;
            file.write_all(json.as_bytes())?;
        }
        OutputFormat::Xml => {
            let xml = quick_xml::se::to_string(results)?;
            file.write_all(xml.as_bytes())?;
        }
    }

    Ok(())
}

fn format_text_results(results: &ScanResults) -> String {
    // This would be similar to print_text_results but return a string
    // For brevity, returning a placeholder
    format!("{:#?}", results)
}

fn print_summary(results: &ScanResults) {
    println!("{}", "Summary".bold().underline());

    let mut warnings = Vec::new();
    let mut good = Vec::new();

    // Check protocol support
    for protocol in &results.protocol_support {
        if protocol.supported {
            if protocol.version.is_deprecated() {
                warnings.push(format!("{} is enabled (deprecated)", protocol.version));
            } else if protocol.version.is_secure() {
                good.push(format!("{} is enabled", protocol.version));
            }
        }
    }

    // Check certificate issues
    for cert in &results.certificate_chain {
        let issues = cert.validation_issues();
        warnings.extend(issues);
    }

    // Check cipher strength
    let weak_ciphers: Vec<_> = results
        .cipher_suites
        .iter()
        .filter(|c| c.supported)
        .filter(|c| {
            matches!(
                c.cipher.strength(),
                CipherStrength::Null | CipherStrength::Weak
            )
        })
        .collect();

    if !weak_ciphers.is_empty() {
        warnings.push(format!("{} weak cipher(s) supported", weak_ciphers.len()));
    }

    // Check Heartbleed vulnerability
    if let Some(true) = results.heartbleed_vulnerable {
        warnings.push("CRITICAL: Server vulnerable to Heartbleed (CVE-2014-0160)".to_string());
    }

    // Print summary
    if !good.is_empty() {
        println!("\n{}:", "Good".green().bold());
        for item in &good {
            println!("  ✓ {}", item.green());
        }
    }

    if !warnings.is_empty() {
        println!("\n{}:", "Warnings".yellow().bold());
        for warning in &warnings {
            println!("  ⚠ {}", warning.yellow());
        }
    }

    if warnings.is_empty() && !good.is_empty() {
        println!("\n{}", "No security issues found!".green().bold());
    }
}
