import requests
from bs4 import BeautifulSoup
import ssl
import socket
from builtwith import builtwith

def get_ssl_info(domain):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            return cert

def analyze_headers(url):
    response = requests.get(url)
    headers = response.headers
    return {
        "CSP": headers.get("Content-Security-Policy", "Not Configured"),
        "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not Configured"),
    }

def main():
    url = "https://example.com"
    domain = url.split("//")[1]  

    ssl_info = get_ssl_info(domain)
    print("SSL Info:", ssl_info)

    tech_info = builtwith(url)
    print("Tecnologias:", tech_info)

    headers_info = analyze_headers(url)
    print("Headers:", headers_info)

if __name__ == "__main__":
    main()
