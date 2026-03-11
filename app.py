from flask import Flask, render_template, request
import nmap
import whois
import socket
import io
import sys

app = Flask(__name__)

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
        print(f"Scanning {target_ip} for open ports with service and version detection...")
        print("-" * 50)
        
        # Enhanced nmap scan with:
        # -sV: Version detection
        # -sS: SYN scan (faster)
        # -T4: Aggressive timing (faster)
        # -O: OS detection
        # --version-intensity: Level of version detection (0-9)
        nm.scan(target_ip, '1-1024', arguments='-sS -sV -T4 -O --version-intensity 5')
        
        if target_ip not in nm.all_hosts():
            print(f"Target {target_ip} is down or unreachable")
            return output.getvalue()
        
        # Print OS information if available
        if 'osmatch' in nm[target_ip] and nm[target_ip]['osmatch']:
            print("\n[+] OS Detection:")
            for osmatch in nm[target_ip]['osmatch'][:2]:  # Show top 2 OS matches
                print(f"    OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
        
        if not nm[target_ip].all_protocols():
            print("No open ports found or host is filtering")
            return output.getvalue()
            
        for protocol in nm[target_ip].all_protocols():
            print(f"\n[+] {protocol.upper()} Protocol:")
            ports = nm[target_ip][protocol].keys()
            
            if ports:
                for port in sorted(ports):
                    service_info = nm[target_ip][protocol][port]
                    
                    # Basic port and service info
                    print(f"\n    Port: {port}/tcp")
                    print(f"    State: {service_info.get('state', 'unknown')}")
                    
                    # Service name
                    service = service_info.get('name', 'unknown')
                    print(f"    Service: {service}")
                    
                    # Product and version information
                    product = service_info.get('product', '')
                    version = service_info.get('version', '')
                    extrainfo = service_info.get('extrainfo', '')
                    
                    if product:
                        print(f"    Product: {product}")
                    if version:
                        print(f"    Version: {version}")
                    if extrainfo:
                        print(f"    Extra Info: {extrainfo}")
                    
                    # Service tunnel (SSL/TLS)
                    tunnel = service_info.get('tunnel', '')
                    if tunnel:
                        print(f"    Tunnel: {tunnel}")
                    
                    # CPE information
                    if 'cpe' in service_info:
                        cpe_list = service_info['cpe']
                        if cpe_list:
                            print(f"    CPE: {', '.join(cpe_list if isinstance(cpe_list, list) else [cpe_list])}")
                    
                    # Script output if any
                    if 'script' in service_info:
                        print("    Script Results:")
                        for script_name, script_output in service_info['script'].items():
                            # Truncate long script output
                            if len(script_output) > 100:
                                script_output = script_output[:100] + "..."
                            print(f"      {script_name}: {script_output}")
            else:
                print(f"    No open {protocol.upper()} ports found")
        
        # Print scan summary
        print("\n" + "-" * 50)
        print("Scan Summary:")
        print(f"Total hosts scanned: 1")
        print(f"Host status: {'up' if target_ip in nm.all_hosts() else 'down'}")
        print(f"Total open ports found: {sum(len(nm[target_ip][protocol].keys()) for protocol in nm[target_ip].all_protocols())}")
        print(f"Scan completed using: {nm.command_line()}")
        
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
    
    full_output = f"--- Nmap Scan with Service/Version Detection ---\n{port_scan_results}\n\n--- WHOIS Lookup ---\n{whois_results}\n\n--- DNS Lookup ---\n{dns_results}"
    
    return full_output

if __name__ == '__main__':
    app.run(debug=True)