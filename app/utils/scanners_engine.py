import socket
import ssl
import datetime
import urllib.parse
import requests

def analyze_security_headers(target_url: str) -> dict:
    """Analyze HTTP security headers and SSL configuration of a target URL."""
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
        
    parsed = urllib.parse.urlparse(target_url)
    domain = parsed.netloc or parsed.path
    is_https = parsed.scheme == 'https'
    
    results = {
        "url": target_url,
        "domain": domain,
        "is_https": is_https,
        "score": 100,
        "grade": "A+",
        "headers": {},
        "missing_headers": [],
        "warnings": [],
        "passed": [],
        "ssl_info": None,
        "response_time_ms": 0
    }
    
    # Expected Security Headers and criteria
    standard_headers = {
        "Strict-Transport-Security": {
            "name": "Strict-Transport-Security (HSTS)",
            "weight": 20,
            "description": "Enforces HTTPS connections and prevents SSL stripping attacks."
        },
        "Content-Security-Policy": {
            "name": "Content-Security-Policy (CSP)",
            "weight": 25,
            "description": "Restricts sources of executable scripts, mitigating Cross-Site Scripting (XSS)."
        },
        "X-Frame-Options": {
            "name": "X-Frame-Options",
            "weight": 15,
            "description": "Prevents Clickjacking by disallowing framing in malicious iframes."
        },
        "X-Content-Type-Options": {
            "name": "X-Content-Type-Options",
            "weight": 10,
            "description": "Prevents MIME-sniffing vulnerabilities by enforcing declared Content-Type."
        },
        "Referrer-Policy": {
            "name": "Referrer-Policy",
            "weight": 10,
            "description": "Protects user privacy by controlling referrer data sent to third parties."
        },
        "Permissions-Policy": {
            "name": "Permissions-Policy",
            "weight": 10,
            "description": "Restricts browser features like camera, microphone, and geolocation."
        }
    }
    
    # Perform HTTP request
    try:
        start_time = datetime.datetime.now()
        response = requests.get(
            target_url, 
            timeout=5, 
            headers={'User-Agent': 'SecureVault-CyberScanner/2.0 (+https://securevault.local)'},
            allow_redirects=True,
            verify=False
        )
        end_time = datetime.datetime.now()
        results["response_time_ms"] = round((end_time - start_time).total_seconds() * 1000, 2)
        results["status_code"] = response.status_code
        
        # Check Information disclosure
        server_header = response.headers.get('Server')
        x_powered_by = response.headers.get('X-Powered-By')
        if server_header:
            results["warnings"].append(f"Server header disclosed: '{server_header}' (leaks web server version).")
            results["score"] -= 5
        if x_powered_by:
            results["warnings"].append(f"X-Powered-By header disclosed: '{x_powered_by}' (leaks backend framework).")
            results["score"] -= 5
            
        # Check standard headers
        for h_key, h_info in standard_headers.items():
            val = response.headers.get(h_key)
            if val:
                results["headers"][h_key] = val
                results["passed"].append({
                    "header": h_info["name"],
                    "value": val,
                    "description": h_info["description"]
                })
            else:
                results["score"] -= h_info["weight"]
                results["missing_headers"].append({
                    "header": h_info["name"],
                    "description": h_info["description"],
                    "risk": f"-{h_info['weight']} pts"
                })
                
    except Exception as e:
        results["error"] = f"Failed to connect to target: {str(e)}"
        results["score"] = 0
        results["grade"] = "F"
        return results

    # Check SSL Certificate if HTTPS
    if is_https:
        try:
            hostname = domain.split(':')[0]
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get('notAfter')
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    
                    if not_after:
                        expire_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expire_date - datetime.datetime.utcnow()).days
                    else:
                        expire_date = None
                        days_left = 0
                        
                    results["ssl_info"] = {
                        "issuer": issuer.get('organizationName', issuer.get('commonName', 'Unknown Issuer')),
                        "subject": subject.get('commonName', hostname),
                        "expires_on": str(expire_date) if expire_date else "Unknown",
                        "days_remaining": days_left,
                        "cipher": ssock.cipher(),
                        "tls_version": ssock.version()
                    }
                    if days_left < 15:
                        results["warnings"].append(f"SSL certificate is expiring soon ({days_left} days left).")
                        results["score"] -= 10
        except Exception as e:
            results["ssl_info"] = {"error": f"SSL inspection error: {str(e)}"}
            results["warnings"].append(f"SSL Certificate could not be verified: {str(e)}")
            results["score"] -= 15

    # Clamp score
    results["score"] = max(0, min(100, results["score"]))
    
    if results["score"] >= 90:
        results["grade"] = "A+"
    elif results["score"] >= 80:
        results["grade"] = "A"
    elif results["score"] >= 70:
        results["grade"] = "B"
    elif results["score"] >= 55:
        results["grade"] = "C"
    elif results["score"] >= 40:
        results["grade"] = "D"
    else:
        results["grade"] = "F"
        
    return results

def scan_target_ports(host: str, ports_to_check=None) -> list:
    """Safe targeted port check for cybersecurity asset inventory."""
    if not ports_to_check:
        ports_to_check = [
            (21, 'FTP', 'Insecure File Transfer'),
            (22, 'SSH', 'Secure Shell Remote Access'),
            (80, 'HTTP', 'Unencrypted Web Traffic'),
            (443, 'HTTPS', 'Encrypted TLS Web Traffic'),
            (3306, 'MySQL', 'Database Port'),
            (5432, 'PostgreSQL', 'Database Port'),
            (6379, 'Redis', 'In-Memory Cache Port'),
            (8080, 'HTTP-Proxy', 'Alternative Web Port')
        ]
        
    results = []
    # Strip protocol if present
    clean_host = host.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
    
    for port, service, desc in ports_to_check:
        status = "Closed / Filtered"
        latency = 0
        try:
            start_t = datetime.datetime.now()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.6)
                res = s.connect_ex((clean_host, port))
                latency = round((datetime.datetime.now() - start_t).total_seconds() * 1000, 1)
                if res == 0:
                    status = "Open"
        except Exception:
            status = "Filtered / Error"
            
        results.append({
            "port": port,
            "service": service,
            "description": desc,
            "status": status,
            "latency_ms": latency
        })
        
    return results
