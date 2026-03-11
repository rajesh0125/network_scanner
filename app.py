from flask import Flask, render_template, request
import nmap
import whois
import socket
import os
import io
import sys

app = Flask(__name__)

# Re-incorporate your original scanner functions here
# (copy them from your initial prompt)

def initialize_scanner():
    try:
        nm = nmap.PortScanner()
        return nm
    except nmap.PortScannerError:
        return None
    except Exception as e:
        return None

def safe_get(data, key, default="N/A"):
    result = data.get(key, default)
    if isinstance(result, list) and result:
        return result[0]
    return result if result else default

def get_whois_info(domain):
    output = io.StringIO()
    sys.stdout = output
    try:
        w = whois.whois(domain)
        print(f"WHOIS Information for {domain}:")
        print(f"Domain Name: {safe_get(w, 'domain_name')}")
        print(f"Registrar: {safe_get(w, 'registrar')}")
        print(f"Registrant: {safe_get(w, 'registrant_name')}")
        print(f"Email: {safe_get(w, 'registrant_email')}")
        print(f"Country: {safe_get(w, 'country')}")
        print(f"Creation Date: {safe_get(w, 'creation_date')}")
        print(f"Expiration Date: {safe_get(w, 'expiration_date')}")
        print(f"phone: {safe_get(w, 'phone')}")
    except Exception as e:
        print(f"Error during WHOIS lookup: {e}")
    finally:
        sys.stdout = sys.__stdout__
    return output.getvalue()

def dns_lookup(domain):
    output = io.StringIO()
    sys.stdout = output
    try:
        ip = socket.gethostbyname(domain)
        print(f"The IP address for {domain} is {ip}")
    except socket.gaierror:
        print(f"Could not resolve {domain}")
    finally:
        sys.stdout = sys.__stdout__
    return output.getvalue()

def scan_ports(target_ip):
    output = io.StringIO()
    sys.stdout = output
    nm = initialize_scanner()
    if not nm:
        print("Error: python-nmap not installed or Nmap not found.")
        sys.stdout = sys.__stdout__
        return output.getvalue()
    
    try:
        print(f"Scanning {target_ip} for open ports...")
        nm.scan(target_ip, '1-1024' , arguments='-T4')
        
        if target_ip not in nm.all_hosts():
            print(f"Target {target_ip} is down or unreachable")
            return output.getvalue()
        
        if not nm[target_ip].all_protocols():
            print("No open ports found or host is filtering")
            return output.getvalue()
            
        for protocol in nm[target_ip].all_protocols():
            open_ports = nm[target_ip][protocol].keys()
            if open_ports:
                for port in sorted(open_ports):
                    print(f"Open Port: {port}, Service: {nm[target_ip][protocol][port]['name']}")
            else:
                print(f"No open {protocol.upper()} ports found")
    except Exception as e:
        print(f"Error during port scan: {e}")
    finally:
        sys.stdout = sys.__stdout__
    return output.getvalue()


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_ip = request.form['ipAddress']
    domain = request.form['domainName']
    
    port_scan_results = scan_ports(target_ip)
    whois_results = get_whois_info(domain)
    dns_results = dns_lookup(domain)
    
    full_output = f"--- Nmap Scan ---\n{port_scan_results}\n\n--- WHOIS Lookup ---\n{whois_results}\n\n--- DNS Lookup ---\n{dns_results}"
    
    return full_output

if __name__ == '__main__':
    app.run(debug=True)