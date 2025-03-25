#!/usr/bin/env ruby

require 'optparse'
require 'net/http'
require 'uri'
require 'json'
require 'whois'
require 'resolv'
require 'colorize'
require 'terminal-table'

class DomainIntel
  def initialize(options)
    @domain = options[:domain]
    @output = options[:output]
    @verbose = options[:verbose]
    @results = {
      domain: @domain,
      scan_time: Time.now.to_s,
      whois: {},
      dns: {},
      ssl: {},
      headers: {},
      subdomains: []
    }
  end

  def banner
    puts "╔═════════════════════════════════════════╗".colorize(:cyan)
    puts "║ DomainIntel - Domain Intelligence Tool  ║".colorize(:cyan)
    puts "╚═════════════════════════════════════════╝".colorize(:cyan)
    puts
  end

  def run
    banner
    
    puts "[*] Target domain: #{@domain}".colorize(:yellow)
    puts "[*] Starting scan at #{Time.now}".colorize(:yellow)
    puts
    
    gather_whois
    gather_dns
    check_ssl
    check_headers
    find_subdomains if @verbose
    
    save_results if @output
    display_results
    
    puts
    puts "[+] Scan completed at #{Time.now}".colorize(:green)
  end
  
  private
  
  def gather_whois
    print "[*] Gathering WHOIS information...".colorize(:yellow)
    begin
      client = Whois::Client.new
      whois = client.lookup(@domain)
      
      @results[:whois] = {
        registrar: whois.registrar&.name,
        created_on: whois.created_on&.to_s,
        updated_on: whois.updated_on&.to_s,
        expires_on: whois.expires_on&.to_s,
        status: whois.status&.join(", "),
        nameservers: whois.nameservers&.map(&:name)
      }
      puts " Done".colorize(:green)
    rescue => e
      puts " Error: #{e.message}".colorize(:red)
      @results[:whois][:error] = e.message
    end
  end
  
  def gather_dns
    print "[*] Gathering DNS information...".colorize(:yellow)
    begin
      resolver = Resolv::DNS.new
      
      # A records
      a_records = []
      begin
        resolver.getresources(@domain, Resolv::DNS::Resource::IN::A).each do |r|
          a_records << r.address.to_s
        end
      rescue; end
      
      # AAAA records
      aaaa_records = []
      begin
        resolver.getresources(@domain, Resolv::DNS::Resource::IN::AAAA).each do |r|
          aaaa_records << r.address.to_s
        end
      rescue; end
      
      # MX records
      mx_records = []
      begin
        resolver.getresources(@domain, Resolv::DNS::Resource::IN::MX).each do |r|
          mx_records << { preference: r.preference, exchange: r.exchange.to_s }
        end
      rescue; end
      
      # NS records
      ns_records = []
      begin
        resolver.getresources(@domain, Resolv::DNS::Resource::IN::NS).each do |r|
          ns_records << r.name.to_s
        end
      rescue; end
      
      # TXT records
      txt_records = []
      begin
        resolver.getresources(@domain, Resolv::DNS::Resource::IN::TXT).each do |r|
          txt_records << r.strings.join("")
        end
      rescue; end
      
      @results[:dns] = {
        a: a_records,
        aaaa: aaaa_records,
        mx: mx_records,
        ns: ns_records,
        txt: txt_records
      }
      puts " Done".colorize(:green)
    rescue => e
      puts " Error: #{e.message}".colorize(:red)
      @results[:dns][:error] = e.message
    end
  end
  
  def check_ssl
    print "[*] Checking SSL certificate...".colorize(:yellow)
    begin
      uri = URI::HTTPS.build(host: @domain)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.open_timeout = 10
      http.read_timeout = 10
      
      response = http.get('/')
      cert = http.peer_cert
      
      @results[:ssl] = {
        subject: cert.subject.to_s,
        issuer: cert.issuer.to_s,
        serial: cert.serial.to_s,
        not_before: cert.not_before.to_s,
        not_after: cert.not_after.to_s,
        expired: cert.not_after < Time.now
      }
      puts " Done".colorize(:green)
    rescue => e
      puts " Error: #{e.message}".colorize(:red)
      @results[:ssl][:error] = e.message
    end
  end
  
  def check_headers
    print "[*] Checking HTTP headers...".colorize(:yellow)
    begin
      uri = URI::HTTPS.build(host: @domain)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.open_timeout = 10
      http.read_timeout = 10
      
      response = http.get('/')
      
      security_headers = {
        'Strict-Transport-Security' => response['Strict-Transport-Security'],
        'Content-Security-Policy' => response['Content-Security-Policy'],
        'X-Content-Type-Options' => response['X-Content-Type-Options'],
        'X-Frame-Options' => response['X-Frame-Options'],
        'X-XSS-Protection' => response['X-XSS-Protection'],
        'Referrer-Policy' => response['Referrer-Policy'],
        'Server' => response['Server']
      }
      
      @results[:headers] = {
        status: response.code,
        security_headers: security_headers
      }
      puts " Done".colorize(:green)
    rescue => e
      puts " Error: #{e.message}".colorize(:red)
      @results[:headers][:error] = e.message
    end
  end
  
  def find_subdomains
    print "[*] Searching for common subdomains...".colorize(:yellow)
    common_subdomains = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev', 'stage', 'test', 'admin']
    
    found_subdomains = []
    
    common_subdomains.each do |subdomain|
      fqdn = "#{subdomain}.#{@domain}"
      begin
        Resolv.getaddress(fqdn)
        found_subdomains << fqdn
      rescue Resolv::ResolvError
        # Subdomain not found
      end
    end
    
    @results[:subdomains] = found_subdomains
    puts " Found #{found_subdomains.size} subdomains".colorize(:green)
  end
  
  def save_results
    begin
      File.open(@output, 'w') do |file|
        file.write(JSON.pretty_generate(@results))
      end
      puts "[+] Results saved to #{@output}".colorize(:green)
    rescue => e
      puts "[-] Error saving results: #{e.message}".colorize(:red)
    end
  end
  
  def display_results
    puts
    puts "═════════ Domain Information ═════════".colorize(:cyan)
    
    # WHOIS Information
    puts
    puts "WHOIS Information:".colorize(:light_blue)
    if @results[:whois][:error]
      puts "  Error: #{@results[:whois][:error]}".colorize(:red)
    else
      whois_table = Terminal::Table.new do |t|
        t.add_row ['Registrar', @results[:whois][:registrar]]
        t.add_row ['Created', @results[:whois][:created_on]]
        t.add_row ['Updated', @results[:whois][:updated_on]]
        t.add_row ['Expires', @results[:whois][:expires_on]]
        t.add_row ['Status', @results[:whois][:status]]
        t.add_row ['Nameservers', @results[:whois][:nameservers]&.join(", ")]
      end
      puts whois_table
    end
    
    # DNS Information
    puts
    puts "DNS Records:".colorize(:light_blue)
    if @results[:dns][:error]
      puts "  Error: #{@results[:dns][:error]}".colorize(:red)
    else
      puts "A Records:".colorize(:yellow)
      @results[:dns][:a].each { |record| puts "  #{record}".colorize(:white) }
      
      puts "AAAA Records:".colorize(:yellow)
      @results[:dns][:aaaa].each { |record| puts "  #{record}".colorize(:white) }
      
      puts "MX Records:".colorize(:yellow)
      @results[:dns][:mx].each { |record| puts "  #{record[:preference]} #{record[:exchange]}".colorize(:white) }
      
      puts "NS Records:".colorize(:yellow)
      @results[:dns][:ns].each { |recor
