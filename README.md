# tlsferret 🦊🔒

![GitHub release](https://img.shields.io/github/release/Yannvvv/tlsferret.svg?style=flat-square&color=blue)

Welcome to **tlsferret**, a fast and comprehensive SSL/TLS scanner built in Rust. Inspired by [rbsec/sslscan](https://github.com/rbsec/sslscan), tlsferret provides a reliable way to assess the security of SSL/TLS implementations. 

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Topics](#topics)
- [Contributing](#contributing)
- [License](#license)
- [Links](#links)

## Features

- **Fast Scanning**: Leverage Rust's performance for quick and efficient scans.
- **Comprehensive Analysis**: Get detailed reports on certificates, cipher suites, and vulnerabilities.
- **Command-Line Tool**: Simple and straightforward command-line interface for easy usage.
- **Post-Quantum Cryptography**: Stay ahead with support for modern cryptographic standards.
- **Flexible Output**: Customize the output format to suit your needs.

## Installation

To get started with tlsferret, you can download the latest release from our [Releases section](https://github.com/Yannvvv/tlsferret/releases). Make sure to download the appropriate file for your operating system and execute it as per the instructions provided.

### Prerequisites

Before installing, ensure you have the following:

- A compatible operating system (Linux, macOS, or Windows).
- Rust installed on your machine (if you want to build from source).

### Building from Source

If you prefer to build tlsferret from source, follow these steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/Yannvvv/tlsferret.git
   cd tlsferret
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Run the scanner:

   ```bash
   ./target/release/tlsferret <target>
   ```

## Usage

Using tlsferret is straightforward. Once installed, you can run it from the command line.

### Basic Command

To scan a target, simply run:

```bash
tlsferret <target>
```

Replace `<target>` with the domain or IP address you want to scan.

### Options

You can customize your scan with various options:

- `-p, --port <port>`: Specify a port to scan (default is 443).
- `--verbose`: Enable verbose output for detailed information.
- `--output <file>`: Save the scan results to a specified file.

### Example

```bash
tlsferret --verbose --output results.txt example.com
```

This command scans `example.com` and saves the results to `results.txt` while providing detailed output.

## Topics

This repository covers a variety of topics related to SSL/TLS security:

- **Certificate**: Analyze the validity and configuration of SSL/TLS certificates.
- **Cipher**: Assess the strength of cipher suites in use.
- **Cipher Suites**: Discover which cipher suites are supported by the server.
- **Command-Line Tool**: Utilize a user-friendly command-line interface.
- **Cryptography**: Understand the cryptographic principles behind SSL/TLS.
- **Post-Quantum Cryptography**: Explore modern cryptographic methods.
- **Rust**: Built with Rust for performance and safety.
- **SSL**: Evaluate SSL implementations.
- **STARTTLS**: Support for STARTTLS on various protocols.

## Contributing

We welcome contributions from the community! If you would like to help improve tlsferret, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch and create a pull request.

For detailed guidelines, please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) file in the repository.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Links

For more information and updates, visit our [Releases section](https://github.com/Yannvvv/tlsferret/releases). Here you can find the latest versions and download files for execution.

![Scan](https://img.shields.io/badge/Scan-Now-brightgreen)

If you have any questions or feedback, feel free to open an issue on GitHub. We appreciate your interest in tlsferret!