DomainIntel
Domain Intelligence Tool
DomainIntel is a Ruby-based cybersecurity tool that gathers comprehensive intelligence about domains, helping security professionals assess potential threats and vulnerabilities.

Features
WHOIS information retrieval
DNS record enumeration (A, AAAA, MX, NS, TXT)
SSL certificate analysis
HTTP security header checking
Common subdomain discovery
Colorized console output with tables
Requirements
Ruby 2.6+
Ruby gems: whois, resolv, colorize, terminal-table, json
Installation
bash

Hide
# Clone the repository
git clone https://github.com/yourusername/DomainIntel.git
cd DomainIntel

# Install dependencies
bundle install

# Make executable
chmod +x domain_intel.rb
Usage
bash

Hide
./domain_intel.rb [options]

# Examples:
./domain_intel.rb --domain example.com
./domain_intel.rb --domain example.com --output report.json
./domain_intel.rb --domain example.com --verbose
Options
--domain DOMAIN: Target domain to analyze (required)
--output FILE: Save results to JSON file
--verbose: Enable verbose mode with additional checks
License
This tool is provided for legitimate security assessment and research purposes only
