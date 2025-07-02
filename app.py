import json
import random
import re
import time
import os
from datetime import datetime
from functools import wraps
from os import environ

from flask import Flask, Response, jsonify, request, render_template

IP_SCORES = {}
LOG_FILE = "telosmiligramme.log"
LOGS_DIR = "logs"

app = Flask(__name__)


def log_event(level, event_type, details):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "level": level,
        "event_type": event_type,
        "source_ip": request.remote_addr,
        "request": {
            "method": request.method,
            "path": request.path,
            "headers": dict(request.headers),
            "args": request.args,
            "body": request.get_data(as_text=True),
        },
        "details": details,
    }

    ip_score = IP_SCORES.get(request.remote_addr, 0)
    log_entry["ip_score"] = ip_score

    print(json.dumps(log_entry))

    # Write to main log file
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    
    # Write to daily log file in logs directory
    os.makedirs(LOGS_DIR, exist_ok=True)
    daily_log_file = os.path.join(LOGS_DIR, f"telosmiligramme-{datetime.utcnow().strftime('%Y-%m-%d')}.log")
    with open(daily_log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")


def randomized_delay(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        delay = random.uniform(0.1, 0.5)
        time.sleep(delay)
        return func(*args, **kwargs)

    return wrapper


def analyze_and_score(threat_type, payload):
    ip = request.remote_addr
    score_increase = 0
    details = {"threat_type": "none", "payload": payload}

    if threat_type == "SQLi":
        # Patterns SQL Injection étendus
        sqli_patterns = [
            # Boolean-based injections
            r"(\'|\")\s*OR\s*(\'|\")\d(\'|\")\s*=\s*(\'|\")\d",
            r"(\'|\")\s*OR\s*(\'|\").*?(\'|\")\s*=\s*(\'|\").*?(\'|\")",
            r"(\'|\")\s*AND\s*(\'|\")\d(\'|\")\s*=\s*(\'|\")\d",
            r"(\'|\")\s*(OR|AND)\s*(\'|\").*?(\'|\")",
            r"\b(true|false)\s*(OR|AND)\s*(true|false)\b",
            
            # Union-based injections
            r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b",
            r"UNION\s+(ALL\s+)?SELECT",
            r"SELECT\s+.*\s+FROM\s+",
            r"INSERT\s+INTO\s+",
            r"UPDATE\s+.*\s+SET\s+",
            r"DELETE\s+FROM\s+",
            
            # Error-based injections
            r"(CAST|CONVERT|EXTRACTVALUE|UPDATEXML|XMLTYPE)",
            r"(GROUP_CONCAT|CONCAT|SUBSTRING|MID|LEFT|RIGHT)",
            r"(SLEEP|WAITFOR|DELAY|BENCHMARK)",
            
            # Time-based injections
            r"(SLEEP|WAITFOR\s+DELAY|BENCHMARK|PG_SLEEP)",
            r"\bIF\s*\(.*,.*SLEEP\(",
            r"\bIF\s*\(.*,.*WAITFOR\s+DELAY",
            
            # Database specific
            r"(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS|DUAL)",
            r"(@@VERSION|@@SERVERNAME|USER\(\)|DATABASE\(\))",
            r"(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)",
            
            # Special characters and operators
            r"['\"];?\s*(#|--|\|\|)",
            r"['\"];?\s*\/\*.*\*\/",
            r"\|\|.*\|\|",
            r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP)",
            
            # Hex encoding
            r"0x[0-9a-fA-F]+",
            r"CHAR\(\d+\)",
            
            # Comment bypasses
            r"\/\*!.*\*\/",
            r"\/\*.*\*\/",
            r"--[^\r\n]*",
            r"#[^\r\n]*",
        ]
        
        for pattern in sqli_patterns:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                details["threat_type"] = "SQLi"
                details["pattern_matched"] = pattern
                score_increase = 10
                break
                
    elif threat_type == "XSS":
        # Patterns XSS étendus
        xss_patterns = [
            # Script tags
            r"<script[^>]*>.*?</script>",
            r"<script[^>]*>",
            r"</script>",
            
            # Event handlers
            r"on\w+\s*=\s*['\"]?[^'\"]*['\"]?",
            r"on(load|click|error|focus|blur|change|submit|reset|select|resize|scroll|unload|beforeunload|hashchange|pagehide|pageshow|popstate|storage|online|offline|message)",
            
            # JavaScript URIs
            r"javascript\s*:",
            r"vbscript\s*:",
            r"data\s*:[^,]*,.*script",
            
            # HTML entities and encoding
            r"&[#x]?[0-9a-fA-F]+;",
            r"&#x[0-9a-fA-F]+;",
            r"&#\d+;",
            
            # Tag injections
            r"<(iframe|embed|object|applet|form|input|img|svg|math|style|link|meta|base)[^>]*>",
            r"<\/?(iframe|embed|object|applet|form|input|img|svg|math|style|link|meta|base)",
            
            # CSS injections
            r"expression\s*\(",
            r"@import\s+",
            r"behaviour\s*:",
            r"-moz-binding\s*:",
            
            # Advanced XSS
            r"String\.fromCharCode\s*\(",
            r"eval\s*\(",
            r"setTimeout\s*\(",
            r"setInterval\s*\(",
            r"Function\s*\(",
            r"window\.",
            r"document\.",
            r"location\.",
            r"alert\s*\(",
            r"confirm\s*\(",
            r"prompt\s*\(",
            
            # Encoded payloads
            r"%3C.*%3E",  # URL encoded < >
            r"\\\\u[0-9a-fA-F]{4}",  # Unicode escape
            r"\\\\x[0-9a-fA-F]{2}",  # Hex escape
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                details["threat_type"] = "XSS"
                details["pattern_matched"] = pattern
                score_increase = 5
                break
                
    elif threat_type == "RCE_Attempt":
        # Extensions de fichiers suspectes étendues
        dangerous_extensions = [
            ".php", ".php3", ".php4", ".php5", ".phtml", ".phps",
            ".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
            ".aspx", ".asp", ".asa", ".asax", ".ascx", ".ashx", ".asmx", ".axd",
            ".sh", ".bash", ".zsh", ".csh", ".ksh",
            ".py", ".pyc", ".pyo", ".pyw", ".pyz",
            ".pl", ".pm", ".cgi",
            ".rb", ".rbw",
            ".exe", ".com", ".bat", ".cmd", ".scr", ".pif",
            ".jar", ".war", ".ear",
            ".dll", ".so", ".dylib",
            ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
            ".ps1", ".psm1", ".psd1", ".ps1xml", ".pssc", ".psrc", ".cdxml"
        ]
        
        # Commandes système suspectes
        command_patterns = [
            r"\b(cat|type|more|less|head|tail|grep|find|locate|which|whereis)\b",
            r"\b(ls|dir|pwd|cd|mkdir|rmdir|rm|del|copy|cp|mv|move)\b",
            r"\b(chmod|chown|chgrp|ps|top|kill|killall|jobs|nohup|bg|fg)\b",
            r"\b(wget|curl|nc|netcat|telnet|ssh|scp|ftp|tftp)\b",
            r"\b(echo|printf|print|write|tee|awk|sed|tr|cut|sort|uniq|wc)\b",
            r"\b(mount|umount|df|du|fdisk|lsblk|blkid|lsof|netstat|ss|ifconfig|ip)\b",
            r"\b(su|sudo|passwd|adduser|useradd|userdel|usermod|groups|id|whoami|w|who|last|history)\b",
            r"\b(systemctl|service|crontab|at|batch|nohup|screen|tmux)\b",
            r"\b(python|python3|perl|ruby|node|java|javac|gcc|g\+\+|make|cmake)\b",
            r"\b(git|svn|hg|cvs|bzr)\b",
            r"\b(mysql|psql|sqlite|mongo|redis-cli)\b",
            r"\b(docker|kubectl|helm|terraform|ansible)\b",
            
            # Command injection patterns
            r"[;&|`$(){}[\]<>]",
            r"\$\(.*\)",
            r"`.*`",
            r"\|\s*\w+",
            r"&&\s*\w+",
            r"\|\|\s*\w+",
            r";\s*\w+",
            
            # File paths
            r"/etc/passwd",
            r"/etc/shadow",
            r"/etc/hosts",
            r"/etc/hostname",
            r"/proc/version",
            r"/proc/cpuinfo",
            r"/proc/meminfo",
            r"/var/log/",
            r"/tmp/",
            r"/home/",
            r"/root/",
            r"C:\\Windows\\",
            r"C:\\Users\\",
            r"C:\\temp\\",
        ]
        
        # Vérifier les extensions
        for ext in dangerous_extensions:
            if payload.lower().endswith(ext):
                details["threat_type"] = "RCE_Attempt"
                details["detected_extension"] = ext
                score_increase = 20
                break
        
        # Vérifier les patterns de commandes
        if score_increase == 0:
            for pattern in command_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    details["threat_type"] = "RCE_Attempt"
                    details["pattern_matched"] = pattern
                    score_increase = 15
                    break

    if score_increase > 0:
        IP_SCORES[ip] = IP_SCORES.get(ip, 0) + score_increase
        log_event(
            "WARNING",
            "ThreatDetected",
            {
                "threat_type": details["threat_type"],
                "payload": payload,
                "score_increase": score_increase,
            },
        )

    return details


def detect_additional_threats(payload, headers=None, method=None, path=None):
    """
    Détecte des menaces additionnelles non couvertes par les patterns principaux
    """
    threats = []
    
    # Directory Traversal / Path Traversal
    path_traversal_patterns = [
        r"\.\.\/",
        r"\.\.[\\]",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"..%252f",
        r"..%255c",
        r"\.\./",
        r"\.\.\\",
    ]
    
    for pattern in path_traversal_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            threats.append({
                "threat_type": "Path_Traversal",
                "pattern": pattern,
                "score": 8
            })
            break
    
    # Local File Inclusion (LFI) / Remote File Inclusion (RFI)
    lfi_rfi_patterns = [
        r"(file|http|https|ftp|ftps|sftp|data|php|expect|zip|phar|dict|ogg|rar)://",
        r"(include|require|include_once|require_once)\s*\(",
        r"file_get_contents\s*\(",
        r"readfile\s*\(",
        r"fopen\s*\(",
        r"fread\s*\(",
        r"fgets\s*\(",
        r"file\s*\(",
        r"show_source\s*\(",
        r"highlight_file\s*\(",
    ]
    
    for pattern in lfi_rfi_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            threats.append({
                "threat_type": "File_Inclusion",
                "pattern": pattern,
                "score": 12
            })
            break
    
    # LDAP Injection
    ldap_patterns = [
        r"\(\s*\|\s*\(",
        r"\(\s*&\s*\(",
        r"\*\)",
        r"\(\s*objectClass\s*=",
        r"\(\s*cn\s*=",
        r"\(\s*uid\s*=",
        r"\(\s*mail\s*=",
    ]
    
    for pattern in ldap_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            threats.append({
                "threat_type": "LDAP_Injection",
                "pattern": pattern,
                "score": 9
            })
            break
    
    # XXE (XML External Entity)
    xxe_patterns = [
        r"<!ENTITY",
        r"<!DOCTYPE.*\[",
        r"SYSTEM\s+['\"]",
        r"PUBLIC\s+['\"]",
        r"&\w+;",
        r"<?xml",
        r"<!ELEMENT",
        r"<!ATTLIST",
    ]
    
    for pattern in xxe_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            threats.append({
                "threat_type": "XXE_Injection",
                "pattern": pattern,
                "score": 15
            })
            break
    
    # SSRF detection removed - commented out for simplification
    # ssrf_patterns = [...]
    
    # NoSQL Injection
    nosql_patterns = [
        r"\$ne\s*:",
        r"\$gt\s*:",
        r"\$lt\s*:",
        r"\$gte\s*:",
        r"\$lte\s*:",
        r"\$in\s*:",
        r"\$nin\s*:",
        r"\$exists\s*:",
        r"\$regex\s*:",
        r"\$where\s*:",
        r"\$or\s*:",
        r"\$and\s*:",
        r"\$not\s*:",
        r"true.*\|\|.*true",
        r"false.*\|\|.*false",
    ]
    
    for pattern in nosql_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            threats.append({
                "threat_type": "NoSQL_Injection",
                "pattern": pattern,
                "score": 11
            })
            break
    
    # Template Injection (SSTI)
    ssti_patterns = [
        r"\{\{.*\}\}",
        r"\{%.*%\}",
        r"\$\{.*\}",
        r"<%.*%>",
        r"#\{.*\}",
        r"\[\[.*\]\]",
        r"__import__",
        r"__builtins__",
        r"__globals__",
        r"config\.",
        r"self\.__",
    ]
    
    for pattern in ssti_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            threats.append({
                "threat_type": "Template_Injection",
                "pattern": pattern,
                "score": 14
            })
            break
    
    # Deserialization Attacks
    deserialization_patterns = [
        r"(java\.lang\.|java\.util\.|java\.io\.)",
        r"(ObjectInputStream|readObject|writeObject)",
        r"(pickle\.loads|pickle\.load|cPickle)",
        r"(__reduce__|__setstate__|__getstate__)",
        r"(base64|b64decode|b64encode)",
        r"(serialize|unserialize|deserialize)",
        r"O:\d+:",  # PHP serialized object
        r"a:\d+:",  # PHP serialized array
    ]
    
    for pattern in deserialization_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            threats.append({
                "threat_type": "Deserialization_Attack",
                "pattern": pattern,
                "score": 16
            })
            break
    
    # User-Agent based attacks
    if headers and 'User-Agent' in headers:
        ua = headers['User-Agent']
        suspicious_ua_patterns = [
            r"(sqlmap|havij|pangolin|jsql|bsqlbf)",  # SQL injection tools
            r"(nikto|nessus|openvas|acunetix|netsparker)",  # Vulnerability scanners
            r"(masscan|nmap|zmap|unicornscan)",  # Port scanners
            r"(metasploit|msfconsole|meterpreter)",  # Exploitation frameworks
            r"(burp|owasp|zap|w3af|skipfish)",  # Web security tools
            r"(python-requests|urllib|curl|wget)",  # Scripted requests
            r"(bot|crawler|spider|scraper)",  # Automated tools
        ]
        
        for pattern in suspicious_ua_patterns:
            if re.search(pattern, ua, re.IGNORECASE):
                threats.append({
                    "threat_type": "Suspicious_User_Agent",
                    "pattern": pattern,
                    "score": 3
                })
                break
    
    return threats

def check_request_anomalies(method, path, headers, body_size=0):
    """
    Détecte des anomalies dans la structure de la requête
    """
    anomalies = []
    
    # Méthodes HTTP suspectes
    if method in ['TRACE', 'TRACK', 'DEBUG', 'PATCH', 'CONNECT']:
        anomalies.append({
            "anomaly_type": "Suspicious_HTTP_Method",
            "details": f"Method: {method}",
            "score": 4
        })
    
    # Headers suspects
    suspicious_headers = [
        'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
        'X-Cluster-Client-IP', 'X-Remote-IP', 'X-Remote-Addr'
    ]
    
    if headers:
        for header in suspicious_headers:
            if header in headers:
                value = headers[header]
                # Check for header injection
                if any(char in value for char in ['\n', '\r', '\0']):
                    anomalies.append({
                        "anomaly_type": "Header_Injection",
                        "details": f"Header: {header}",
                        "score": 7
                    })
    
    # Body size anormalement grand (potentiel DoS)
    if body_size > 10 * 1024 * 1024:  # 10MB
        anomalies.append({
            "anomaly_type": "Large_Body_Size",
            "details": f"Size: {body_size} bytes",
            "score": 6
        })
    
    # Paths suspects
    suspicious_paths = [
        r"/\.well-known/",
        r"/admin/",
        r"/administrator/",
        r"/wp-admin/",
        r"/wp-content/",
        r"/phpmyadmin/",
        r"/mysql/",
        r"/database/",
        r"/backup/",
        r"/test/",
        r"/dev/",
        r"/api/",
        r"/config/",
        r"/\.git/",
        r"/\.svn/",
        r"/\.env",
    ]
    
    for pattern in suspicious_paths:
        if re.search(pattern, path, re.IGNORECASE):
            anomalies.append({
                "anomaly_type": "Suspicious_Path_Access",
                "details": f"Path: {path}",
                "score": 2
            })
            break
    
    return anomalies


@app.route("/")
@randomized_delay
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@randomized_delay
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Détections principales
        analyze_and_score("SQLi", username)
        analyze_and_score("SQLi", password)
        
        # Détections additionnelles
        additional_threats_username = detect_additional_threats(username, dict(request.headers), request.method, request.path)
        additional_threats_password = detect_additional_threats(password, dict(request.headers), request.method, request.path)
        
        # Anomalies de requête
        anomalies = check_request_anomalies(request.method, request.path, dict(request.headers), len(request.get_data()))
        
        # Traitement des menaces additionnelles
        for threat in additional_threats_username + additional_threats_password:
            IP_SCORES[request.remote_addr] = IP_SCORES.get(request.remote_addr, 0) + threat['score']
            log_event(
                "WARNING",
                "ThreatDetected",
                {
                    "threat_type": threat['threat_type'],
                    "payload": username if threat in additional_threats_username else password,
                    "pattern": threat.get('pattern', ''),
                    "score_increase": threat['score']
                }
            )
        
        # Traitement des anomalies
        for anomaly in anomalies:
            IP_SCORES[request.remote_addr] = IP_SCORES.get(request.remote_addr, 0) + anomaly['score']
            log_event(
                "INFO",
                "RequestAnomaly",
                {
                    "anomaly_type": anomaly['anomaly_type'],
                    "details": anomaly['details'],
                    "score_increase": anomaly['score']
                }
            )

        log_event(
            "INFO",
            "LoginAttempt",
            {"username": username, "password": "REDACTED"},
        )

        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Invalid username or password. Please try again.",
                }
            ),
            401,
        )

    return render_template("login.html")


@app.route("/search", methods=["GET"])
@randomized_delay
def search():
    query = request.args.get("query", "")

    # Détections principales
    analyze_and_score("XSS", query)
    
    # Détections additionnelles sur la query
    additional_threats = detect_additional_threats(query, dict(request.headers), request.method, request.path)
    
    # Anomalies de requête
    anomalies = check_request_anomalies(request.method, request.path, dict(request.headers), len(request.get_data()))
    
    # Traitement des menaces additionnelles
    for threat in additional_threats:
        IP_SCORES[request.remote_addr] = IP_SCORES.get(request.remote_addr, 0) + threat['score']
        log_event(
            "WARNING",
            "ThreatDetected",
            {
                "threat_type": threat['threat_type'],
                "payload": query,
                "pattern": threat.get('pattern', ''),
                "score_increase": threat['score']
            }
        )
    
    # Traitement des anomalies
    for anomaly in anomalies:
        IP_SCORES[request.remote_addr] = IP_SCORES.get(request.remote_addr, 0) + anomaly['score']
        log_event(
            "INFO",
            "RequestAnomaly",
            {
                "anomaly_type": anomaly['anomaly_type'],
                "details": anomaly['details'],
                "score_increase": anomaly['score']
            }
        )

    log_event("INFO", "SearchQuery", {"query": query})

    return render_template("search.html", query=query)


@app.route("/upload", methods=["GET", "POST"])
@randomized_delay
def upload():
    if request.method == "POST":
        if "file" not in request.files:
            return jsonify({"status": "error", "message": "No file part"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"status": "error", "message": "No selected file"}), 400

        # Détections principales
        analyze_and_score("RCE_Attempt", file.filename)
        
        # Détections additionnelles sur le nom de fichier
        additional_threats = detect_additional_threats(file.filename, dict(request.headers), request.method, request.path)
        
        # Anomalies de requête
        anomalies = check_request_anomalies(request.method, request.path, dict(request.headers), len(request.get_data()))
        
        # Traitement des menaces additionnelles
        for threat in additional_threats:
            IP_SCORES[request.remote_addr] = IP_SCORES.get(request.remote_addr, 0) + threat['score']
            log_event(
                "WARNING",
                "ThreatDetected",
                {
                    "threat_type": threat['threat_type'],
                    "payload": file.filename,
                    "pattern": threat.get('pattern', ''),
                    "score_increase": threat['score']
                }
            )
        
        # Traitement des anomalies
        for anomaly in anomalies:
            IP_SCORES[request.remote_addr] = IP_SCORES.get(request.remote_addr, 0) + anomaly['score']
            log_event(
                "INFO",
                "RequestAnomaly",
                {
                    "anomaly_type": anomaly['anomaly_type'],
                    "details": anomaly['details'],
                    "score_increase": anomaly['score']
                }
            )

        log_event(
            "INFO",
            "FileUpload",
            {
                "filename": file.filename,
                "content_type": file.content_type,
            },
        )

        return (
            jsonify(
                {
                    "status": "success",
                    "message": f"File '{file.filename}' processed successfully.",
                }
            ),
            200,
        )
    return render_template("upload.html")


@app.route("/admin", methods=["GET", "POST"])
@randomized_delay
def admin():
    auth = request.authorization
    if not auth:
        log_event("INFO", "AdminAccessAttempt", {"message": "No auth header"})
    else:
        log_event(
            "WARNING",
            "AdminAuthAttempt",
            {"username": auth.username, "password": auth.password},
        )
        IP_SCORES[request.remote_addr] = IP_SCORES.get(request.remote_addr, 0) + 2

    return Response(
        "Forbidden: You don't have permission to access this resource.",
        403,
        {"WWW-Authenticate": 'Basic realm="Admin Area"'},
    )


@app.route("/robots.txt", methods=["GET"])
@randomized_delay
def robots_txt():
    content = """User-agent: *
Disallow: /admin
Disallow: /config
Disallow: /backup.zip
Disallow: /api/v1/users
"""
    return Response(content, mimetype="text/plain")


if __name__ == "__main__":
    port = int(environ.get("BACKEND_PORT", 8080))
    print(f"Starting telosmiligramme server on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)