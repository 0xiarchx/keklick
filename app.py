from flask import Flask, request, Response, jsonify, render_template, stream_with_context
import subprocess
import json
import re
import time
import socket
from flask_cors import CORS
from ipwhois import IPWhois
import requests
import urllib3
import dns.resolver
import ssl
import OpenSSL.crypto as crypto
import datetime
from concurrent.futures import ThreadPoolExecutor
import whois
import base64
import os
import platform
from functools import lru_cache

app = Flask(__name__, static_folder='static', static_url_path='/static')

urllib3.disable_warnings()

CORS(app)


API_KEYS = {
    "abuseipdb": "",
    "otx": ""
}


GEOIP_DB_PATH = "GeoLite2-City.mmdb"


def is_httpx_available():
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["where", "httpx"], capture_output=True, text=True)
            return "httpx" in result.stdout.lower()
        else:
            result = subprocess.run(["which", "httpx"], capture_output=True, text=True)
            return result.returncode == 0
    except Exception:
        return False


def run_command(cmd, shell=False):
    try:
        if platform.system() == "Windows" and shell:
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        else:
            result = subprocess.run(cmd, capture_output=True, text=True)
        return result
    except Exception as e:
        print(f"Command execution error: {e}")
        return None


def rate_limited(max_per_second):
    min_interval = 1.0 / max_per_second
    def decorator(func):
        last_time_called = [0.0]
        def rate_limited_function(*args, **kwargs):
            elapsed = time.time() - last_time_called[0]
            left_to_wait = min_interval - elapsed
            if left_to_wait > 0:
                time.sleep(left_to_wait)
            last_time_called[0] = time.time()
            return func(*args, **kwargs)
        return rate_limited_function
    return decorator

@lru_cache(maxsize=128)
def get_asn_info(ip_address):
    try:
        obj = IPWhois(ip_address)
        res = obj.lookup_rdap()
        asn = res.get('asn')
        asn_description = res.get('asn_description')
        if asn and asn_description:
            return f"{asn} - {asn_description}"
        elif asn:
            return f"{asn}"
        else:
            return "Unknown ASN"
    except Exception as e:
        return f"ASN Error: {str(e)}"

def get_geoip_data(ip_address):
    try:
        
        return {
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "latitude": 0,
            "longitude": 0,
            "timezone": "UTC"
        }
    except Exception as e:
        return {"error": f"GeoIP error: {str(e)}"}

def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(answer) for answer in answers]
        except Exception:
            records[record_type] = []
    
    return records

def get_ssl_certificate(domain):
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        
        
        subject = dict(x509.get_subject().get_components())
        issuer = dict(x509.get_issuer().get_components())
        
        
        subject = {k.decode('utf-8'): v.decode('utf-8') for k, v in subject.items()}
        issuer = {k.decode('utf-8'): v.decode('utf-8') for k, v in issuer.items()}
        
        
        not_before = datetime.datetime.strptime(x509.get_notBefore().decode('utf-8'), '%Y%m%d%H%M%SZ')
        not_after = datetime.datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
        
        
        san = []
        for i in range(x509.get_extension_count()):
            ext = x509.get_extension(i)
            if b'subjectAltName' in ext.get_short_name():
                san_text = ext.__str__()
                san = [name.replace('DNS:', '').strip() for name in san_text.split(',')]
        
        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before.strftime('%Y-%m-%d %H:%M:%S'),
            "not_after": not_after.strftime('%Y-%m-%d %H:%M:%S'),
            "san": san,
            "serial_number": format(x509.get_serial_number(), 'x'),
            "version": x509.get_version(),
            "algorithm": x509.get_signature_algorithm().decode('utf-8')
        }
    except Exception as e:
        return {"error": f"SSL certificate error: {str(e)}"}

def get_whois_info(target, is_ip=False):
    try:
        whois_info = whois.whois(target)
        result = {}
        
        
        for key, value in whois_info.items():
            if isinstance(value, list):
                result[key] = [str(item) for item in value]
            elif isinstance(value, datetime.datetime):
                result[key] = value.strftime('%Y-%m-%d %H:%M:%S')
            else:
                result[key] = str(value) if value else None
        
        return result
    except Exception as e:
        return {"error": f"WHOIS error: {str(e)}"}

def check_domain_status(domain):
    
    if is_httpx_available():
        try:
            
            cmd = [
                "httpx", 
                "-u", domain,
                "-silent",
                "-tech-detect",
                "-status-code",
                "-follow-redirects",
                "-title",      
                "-location",   
                "-random-agent", 
                "-timeout", "5",
                "-json"
            ]
            
            result = run_command(cmd)
            if result and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    
                    url = data.get("url", domain)
                    status_code = data.get("status_code", 0)
                    
                    
                    status_message = {
                        200: "OK",
                        301: "Moved Permanently",
                        302: "Found",
                        303: "See Other", 
                        304: "Not Modified",
                        307: "Temporary Redirect",
                        308: "Permanent Redirect",
                        400: "Bad Request",
                        401: "Unauthorized",
                        403: "Forbidden",
                        404: "Not Found",
                        429: "Too Many Requests",
                        500: "Internal Server Error",
                        502: "Bad Gateway",
                        503: "Service Unavailable",
                        504: "Gateway Timeout"
                    }.get(status_code, f"Status {status_code}")
                    
                    
                    technologies = data.get("technologies", [])
                    tech_str = ",".join(technologies) if technologies else "None"
                    
                    
                    title = data.get("title", "")
                    location = data.get("location", "")
                    
                    
                    return f"{domain} [{status_code}] [{status_message}] [{tech_str}] [{title}] [{location}]"
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"HTTPX error: {str(e)}")
    
    
    
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{domain}"
            response = requests.get(
                url, 
                timeout=3,  
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
                verify=False  
            )
            
            status_code = response.status_code
            status_message = {
                200: "OK",
                301: "Moved Permanently",
                302: "Found",
                303: "See Other", 
                304: "Not Modified",
                307: "Temporary Redirect",
                308: "Permanent Redirect",
                400: "Bad Request",
                401: "Unauthorized",
                403: "Forbidden",
                404: "Not Found",
                429: "Too Many Requests",
                500: "Internal Server Error",
                502: "Bad Gateway",
                503: "Service Unavailable",
                504: "Gateway Timeout"
            }.get(status_code, f"Status {status_code}")
            
            
            technologies = []
            content = response.text.lower()
            tech_markers = {
                "wordpress": "WordPress",
                "jquery": "jQuery",
                "bootstrap": "Bootstrap",
                "react": "React",
                "angular": "Angular",
                "vue": "Vue.js",
                "laravel": "Laravel",
                "php": "PHP",
                "nginx": "Nginx",
                "apache": "Apache",
                "cloudflare": "Cloudflare",
                "akamai": "Akamai",
                "aws": "AWS",
                "azure": "Azure",
                "google cloud": "Google Cloud",
                "docker": "Docker",
                "kubernetes": "Kubernetes",
                "django": "Django",
                "flask": "Flask",
                "node.js": "Node.js",
                "express": "Express",
                "spring": "Spring",
                "java": "Java",
                "python": "Python",
                "ruby": "Ruby",
                "rails": "Rails"
            }
            
            for marker, tech_name in tech_markers.items():
                if marker in content:
                    technologies.append(tech_name)
            
            
            server = response.headers.get('Server')
            if server:
                technologies.append(f"Server:{server}")

            
            powered_by = response.headers.get('X-Powered-By')
            if powered_by:
                technologies.append(f"Powered-By:{powered_by}")
            
            
            title = ""
            title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()
            
            
            location = response.headers.get('Location', '')
            
            tech_str = ",".join(technologies) if technologies else "None"
            return f"{domain} [{status_code}] [{status_message}] [{tech_str}] [{title}] [{location}]"
            
        except Exception as e:
            continue  
    
    
    return f"{domain} [0] [Connection Failed] [undefined] [] []"

def check_ip_availability(ip):
    
    if is_httpx_available():
        try:
            
            cmd = [
                "httpx", 
                "-u", f"http://{ip}",
                "-silent",
                "-tech-detect",
                "-status-code",
                "-follow-redirects",
                "-title",      
                "-location",   
                "-random-agent", 
                "-timeout", "3",
                "-json"
            ]
            
            result = run_command(cmd)
            if result and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    status_code = data.get("status_code", 0)
                    
                    status_message = {
                        200: "OK",
                        301: "Moved Permanently",
                        302: "Found",
                        403: "Forbidden",
                        404: "Not Found",
                        500: "Internal Server Error",
                        503: "Service Unavailable"
                    }.get(status_code, f"Status {status_code}")
                    
                    technologies = data.get("technologies", [])
                    tech_str = ",".join(technologies) if technologies else "N/A"
                    
                    
                    title = data.get("title", "")
                    location = data.get("location", "")
                    
                    return f"{ip} [{status_code}] [{status_message}] [{tech_str}] [{title}] [{location}]"
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            print(f"HTTPX error: {str(e)}")
    
    
    try:
        response = requests.get(
            f"http://{ip}", 
            timeout=2,  
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'},
            verify=False
        )
        status_code = response.status_code
        status_message = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            503: "Service Unavailable"
        }.get(status_code, f"Status {status_code}")
        
        
        title = ""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
        
        
        location = response.headers.get('Location', '')
        
        return f"{ip} [{status_code}] [{status_message}] [N/A] [{title}] [{location}]"
    except:
        return f"{ip} [0] [Connection Failed] [undefined] [] []"

@rate_limited(1)  
def query_abuseipdb(ip):
    try:
        api_key = API_KEYS["abuseipdb"]
        url = f"https://api.abuseipdb.com/api/v2/check"
        
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }
        
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            data = response.json()
            if "data" in data:
                result = {
                    "ip": data["data"]["ipAddress"],
                    "is_public": data["data"]["isPublic"],
                    "abuse_score": data["data"]["abuseConfidenceScore"],
                    "country_code": data["data"]["countryCode"],
                    "country": data["data"]["countryName"],
                    "total_reports": data["data"]["totalReports"],
                    "last_reported": data["data"].get("lastReportedAt"),
                    "domain": data["data"].get("domain"),
                    "isp": data["data"].get("isp"),
                    "usage_type": data["data"].get("usageType")
                }
                return result
            return {"error": "No data"}
        else:
            return {"error": f"AbuseIPDB API error: {response.status_code}"}
    except Exception as e:
        return {"error": f"AbuseIPDB query error: {str(e)}"}

@rate_limited(1)  
def query_otx(target, is_ip=False):
    try:
        api_key = API_KEYS["otx"]
        
        if is_ip:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{target}"
        else:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{target}"
        
        headers = {"X-OTX-API-KEY": api_key}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            result = {}
            
            
            result["pulse_count"] = data.get("pulse_info", {}).get("count", 0)
            result["reputation"] = data.get("reputation", 0)
            
            
            if "pulse_info" in data and "pulses" in data["pulse_info"]:
                pulses = []
                for pulse in data["pulse_info"]["pulses"][:5]:  
                    pulses.append({
                        "name": pulse.get("name"),
                        "created": pulse.get("created"),
                        "tags": pulse.get("tags", [])
                    })
                result["pulses"] = pulses
            
            return result
        else:
            return {"error": f"OTX API error: {response.status_code}"}
    except Exception as e:
        return {"error": f"OTX query error: {str(e)}"}

def check_sandbox(url):
    try:
        
        
        return {
            "status": "completed",
            "risk_score": 75,
            "screenshot": "base64_encoded_screenshot_data",
            "analysis_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "behaviors": [
                "Making changes to the operating system",
                "Creating suspicious network connections",
                "Adding autostart registry entries"
            ]
        }
    except Exception as e:
        return {"error": f"Sandbox error: {str(e)}"}

@app.route('/api/threat_intel', methods=['GET'])
def threat_intel():
    target = request.args.get('target')
    target_type = request.args.get('type', 'auto')
    
    if not target:
        return jsonify({'error': 'Please enter a target (IP or domain).'}), 400
    
    
    is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target)
    
    
    if target_type == 'auto':
        target_type = 'ip' if is_ip else 'domain'
    
    results = {}
    
    
    if target_type == 'ip':
        results['asn_info'] = get_asn_info(target)
        results['geoip'] = get_geoip_data(target)
        results['whois'] = get_whois_info(target, is_ip=True)
    else:
        try:
            
            domain_ips = socket.gethostbyname_ex(target)[2]
            if domain_ips:
                primary_ip = domain_ips[0]
                results['primary_ip'] = primary_ip
                results['all_ips'] = domain_ips
                results['asn_info'] = get_asn_info(primary_ip)
                results['geoip'] = get_geoip_data(primary_ip)
                results['dns_records'] = get_dns_records(target)
                results['ssl_certificate'] = get_ssl_certificate(target)
                results['whois'] = get_whois_info(target, is_ip=False)
        except Exception as e:
            results['error'] = f"DNS resolution error: {str(e)}"
    
    
    with ThreadPoolExecutor(max_workers=2) as executor:
        if target_type == 'ip':
            
            abuse_future = executor.submit(query_abuseipdb, target)
            otx_future = executor.submit(query_otx, target, True)
            
            results['abuseipdb'] = abuse_future.result()
            results['otx'] = otx_future.result()
            
        else:
            
            otx_future = executor.submit(query_otx, target, False)
            
            results['otx'] = otx_future.result()
    
    return jsonify(results)

@app.route('/api/analyze_ssl', methods=['GET'])
def analyze_ssl():
    domain = request.args.get('domain')
    
    if not domain:
        return jsonify({'error': 'Please enter a domain.'}), 400
    
    try:
        ssl_info = get_ssl_certificate(domain)
        return jsonify(ssl_info)
    except Exception as e:
        return jsonify({'error': f"SSL analysis error: {str(e)}"}), 500

@app.route('/api/dns_records', methods=['GET'])
def dns_records():
    domain = request.args.get('domain')
    
    if not domain:
        return jsonify({'error': 'Please enter a domain.'}), 400
    
    try:
        records = get_dns_records(domain)
        return jsonify(records)
    except Exception as e:
        return jsonify({'error': f"DNS record error: {str(e)}"}), 500

@app.route('/api/whois', methods=['GET'])
def whois_lookup():
    target = request.args.get('target')
    target_type = request.args.get('type', 'auto')
    
    if not target:
        return jsonify({'error': 'Please enter a target (IP or domain).'}), 400
    
    
    is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target)
    
    
    if target_type == 'auto':
        target_type = 'ip' if is_ip else 'domain'
    
    try:
        whois_info = get_whois_info(target, is_ip=(target_type == 'ip'))
        return jsonify(whois_info)
    except Exception as e:
        return jsonify({'error': f"WHOIS error: {str(e)}"}), 500

@app.route('/api/sandbox', methods=['POST'])
def sandbox_analysis():
    data = request.json
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'Please enter a URL.'}), 400
    
    try:
        results = check_sandbox(url)
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f"Sandbox error: {str(e)}"}), 500

@app.route('/search', methods=['GET'])
def search():
    target = request.args.get('target')  
    search_type = request.args.get('type', 'auto')  
    limit = request.args.get('limit', '50')  
    
    if not target:
        return jsonify({'error': 'Please enter a target (IP or domain).'}), 400
    
    
    if limit.lower() == 'all':
        limit = None  
    else:
        try:
            limit = int(limit)
        except ValueError:
            limit = 50  
    
    
    is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target)
    
    
    if search_type == 'auto':
        search_type = 'ip' if is_ip else 'domain'
    
    
    target_ips = []
    asn_info = "N/A"
    
    if search_type == 'domain':
        try:
            
            domain_ips = socket.gethostbyname_ex(target)[2]
            if domain_ips:
                target_ips = domain_ips
                
                asn_info = get_asn_info(domain_ips[0])
        except Exception as e:
            print(f"DNS resolution error: {e}")
            
            target_ips = []

    elif search_type == 'ip':
        
        asn_info = get_asn_info(target)
        target_ips = [target]

    def generate():
        toplam_sonuc = 0  
        
        try:
            if search_type == 'ip' or (search_type == 'domain' and not target_ips):
                
                hedns_cmd = ["hednsextractor", "-target", target, "-only-domains", "-silent"]
                if platform.system() == "Windows":
                    result = run_command(hedns_cmd, shell=True)
                else:
                    result = run_command(hedns_cmd)
                
                
                domains = []
                if result and result.stdout:
                    domains = result.stdout.strip().split('\n')
                
                
                for domain in domains:
                    domain = domain.strip()
                    if domain:
                        
                        if limit is not None and toplam_sonuc >= limit:
                            yield f"event: complete\ndata: {json.dumps({'status': 'complete'})}\n\n"
                            return
                        
                        
                        domain_info = check_domain_status(domain)
                        data = {
                            "target": target, 
                            "domain": domain_info, 
                            "asn_info": asn_info, 
                            "type": "domain"
                        }
                        yield f"data: {json.dumps(data)}\n\n"
                        toplam_sonuc += 1  
                        
                        
                        time.sleep(0.2)
            
            elif search_type == 'domain' and target_ips:
                
                for ip in target_ips:
                    
                    if limit is not None and toplam_sonuc >= limit:
                        yield f"event: complete\ndata: {json.dumps({'status': 'complete'})}\n\n"
                        return
                    
                    ip_info = check_ip_availability(ip)
                    data = {
                        "target": target, 
                        "ip": ip_info, 
                        "type": "ip"
                    }
                    yield f"data: {json.dumps(data)}\n\n"
                    toplam_sonuc += 1  
                    time.sleep(0.2)
                    
                    
                    hedns_cmd = ["hednsextractor", "-target", ip, "-only-domains", "-silent"]
                    if platform.system() == "Windows":
                        result = run_command(hedns_cmd, shell=True)
                    else:
                        result = run_command(hedns_cmd)
                    
                    subdomains = []
                    if result and result.stdout:
                        subdomains = result.stdout.strip().split('\n')
                    
                    for subdomain in subdomains:
                        
                        if limit is not None and toplam_sonuc >= limit:
                            yield f"event: complete\ndata: {json.dumps({'status': 'complete'})}\n\n"
                            return
                        
                        if subdomain.strip():
                            subdomain_info = check_domain_status(subdomain)
                            data = {
                                "target": target, 
                                "domain": subdomain_info, 
                                "parent_ip": ip,
                                "type": "domain"
                            }
                            yield f"data: {json.dumps(data)}\n\n"
                            toplam_sonuc += 1  
                            time.sleep(0.2)
                
                
                yield f"event: complete\ndata: {json.dumps({'status': 'complete'})}\n\n"
                
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            data = {"target": target, "error": error_msg, "asn_info": asn_info}
            yield f"data: {json.dumps(data)}\n\n"
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)