require 'net/http'
require 'nokogiri'
require 'socket'
require 'openssl'

def fetch_ssl_info(domain)
    tcp_client = TCPSocket.new(domain, 443)
    ssl_cliente = OpenSSL::SSL::SSLSocket.new(tcp_client)
    ssl_client.connect
    
    cert = ssl_client.peer_cert
    ssl_client.sysclose
    tcp_client.close

    {
        issuer: cert.issuer.to_s,
        subject: cert.subject.to_s,
        valid_from: cert.not_before,
        valid_to: cert.not_after
    }
end    

def fetch_security_headers(url)
    uri = URI(url)
    response = Net::HTTP.get_response(uri)

    {
        "Content_Security_Policy" => response['content-security-policy'] || 'Not Configured',
        "X-Content-Type-Options" => response['x-content-type-options'] || 'Not Configured'
    }
end

def fecth_technologies(url)
    uri = URI(url)
    response = Net::HTTP.get(uri)
    parsed_html = Nokogiri::HTML(response)

    meta_generator = parsed_html.at('meta[name="generator"]')&.[]('content') || 'Not Found'
    
    {
      "Meta Gnerator" => meta_generator
    }
end

def main
    domain = "example.com"
    url = "https://#{domain}"

    ssl_info = fetch_ssl_info (domain)
    puts "SSL/TLS Info:"
    puts ssl_info


    security_headers = fetch_security_headers(url)
    puts "\nSecurity Headers:"
    puts security_headers

    techonologies = fecth_technologies(url)
    puts "\nTechnologies:"
    puts techonologies
end

main
