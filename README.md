# DomainIntel
## Domain Intelligence Tool

DomainIntel is a comprehensive domain intelligence gathering tool designed for cybersecurity professionals and researchers. DomainIntel automates the collection and analysis of critical domain information including WHOIS data, DNS records, SSL certificates, security headers, and subdomains.

## Features
- **WHOIS Information**: Registrar details, creation/expiration dates, nameservers
- **DNS Records**: A, AAAA, MX, NS, TXT, and SOA records
- **SSL Certificate Analysis**: Validity, expiration, key size, signature algorithm
- **Security Headers Evaluation**: Analysis of HTTP security headers with rating
- **Subdomain Discovery**: Identification of common subdomains
- **Parallel Processing**: Multi-threaded operations for faster scanning
- **JSON Export**: Save all results to a structured JSON file
- **Colorized Output**: Easy-to-read terminal output with color-coded results

## Requirements
- **Ruby 2.6+**
- Required gems:
  - `optparse`
  - `net/http`
  - `uri`
  - `json`
  - `whois`
  - `resolv`
  - `colorize`
  - `terminal-table`
  - `timeout`
  - `openssl`

## Installation

1. **Clone the repository:**
   
    git clone https://github.com/yourusername/domain-intel.git
    cd domain-intel
  

2. **Install required gems:**
   
    gem install whois colorize terminal-table
    ```

3. **Make the script executable:**
   
    chmod +x domain_intel.rb
    ```

## Usage

### Basic Usage
./domain_intel.rb -d example.com
Available Options
-d, --domain DOMAIN : Target domain (required)

-o, --output FILE : Save results to JSON file

-v, --verbose : Enable verbose mode with subdomain scanning

-t, --timeout SECONDS : Set timeout for operations (default: 15)

--threads NUM : Number of threads for subdomain scanning (default: 10)

-h, --help : Show help message

Examples
Basic scan:

./domain_intel.rb -d google.com
Verbose scan with output file:

./domain_intel.rb -d microsoft.com -v -o microsoft_results.json
Scan with custom timeout:

bash
Copiar código
./domain_intel.rb -d facebook.com -t 30
Sample Output
yaml
Copiar código
╔═════════════════════════════════════════╗
║ DomainIntel v1.0.0 - Domain Intelligence Tool ║
╚═════════════════════════════════════════╝

[*] Target domain: example.com
[*] Starting scan at 2025-03-26 06:35:00 -0400
[*] Gathering WHOIS information... Done
[*] Gathering DNS information... Done
[*] Checking SSL certificate... Done
[*] Checking HTTP headers... Done

═════════ Domain Information ═════════

WHOIS Information:
+-------------+----------------------------------+
| Registrar   | ICANN                            |
| Created     | 1995-08-14 04:00:00 UTC          |
| Updated     | 2022-08-14 07:01:31 UTC          |
| Expires     | 2023-08-13 04:00:00 UTC          |
| Status      | clientDeleteProhibited           |
| Nameservers | a.iana-servers.net, b.iana-servers.net |
+-------------+----------------------------------+

DNS Records:
+------------+--------------------------------------+
| Record Type | Value                                |
+------------+--------------------------------------+
| A          | 93.184.216.34                        |
| NS         | a.iana-servers.net                   |
| NS         | b.iana-servers.net                   |
| SOA        | a.iana-servers.net noc.dns.icann.org |
+------------+--------------------------------------+

SSL Certificate:
+-------------------+------------------------------------------+
| Subject           | CN=example.com                           |
| Issuer            | CN=DigiCert TLS RSA SHA256 2020 CA1     |
| Valid From        | 2022-03-14 00:00:00 UTC                 |
| Valid Until       | 2023-03-14 23:59:59 UTC                 |
| Expires In        | 120 days                                |
| Signature Algorithm | sha256WithRSAEncryption                |
| Key Size          | 2048 bits                               |
+-------------------+------------------------------------------+

Security Headers:
+-------------------------+---------------+
| Header                  | Value         |
+-------------------------+---------------+
| Strict-Transport-Security | max-age=31536000 |
| Content-Security-Policy | Not set       |
| X-Content-Type-Options  | nosniff       |
| X-Frame-Options         | SAMEORIGIN    |
| X-XSS-Protection        | 1; mode=block |
| Referrer-Policy         | Not set       |
| Server                  | ECS           |
+-------------------------+---------------+

Security Headers Rating: B
Issues:
  - CSP not defined
  - Referrer-Policy missing

[+] Scan completed at 2025-03-26 06:35:05 -0400
License
MIT License

Copyright (c) 2025 CONSTANZA

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Disclaimer
This tool is intended for legitimate cybersecurity research and testing only. Users must ensure they have proper authorization before scanning any domains they do not own. The author assumes no liability for misuse or any damages resulting from the use of this software.


