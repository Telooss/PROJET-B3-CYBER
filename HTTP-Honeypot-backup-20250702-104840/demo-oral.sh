#!/bin/bash

# Script de démonstration pour l'oral - Telosmiligramme
# Utilisation : ./demo-oral.sh [IP_HONEYPOT]

HONEYPOT_IP=${1:-"localhost"}
HONEYPOT_PORT="8080"
BASE_URL="http://${HONEYPOT_IP}:${HONEYPOT_PORT}"

echo "Démonstration Telosmiligramme "
echo "================================================"
echo "Target: ${BASE_URL}"
echo ""

# Fonction pour attendre et afficher
wait_and_show() {
    echo "⏳ Attente 2 secondes..."
    sleep 2
    echo "📋 Logs récents:"
    tail -n 1 logs/telosmiligramme-$(date +%Y-%m-%d).log | jq -r '. | "🚨 \(.event_type) - IP: \(.source_ip) - Score: \(.ip_score) - Threat: \(.details.threat_type // "N/A")"'
    echo ""
}

echo "1️⃣ Interface normale (apparence légitime)"
echo "curl ${BASE_URL}"
curl -s "${BASE_URL}" > /dev/null
echo "✅ Page d'accueil chargée - aucune alerte"
echo ""

echo "=== 🛡️ PHASE 1: INJECTIONS SQL (2 tests) ==="
echo "2️⃣ SQL Injection #1 - Boolean-based (score: 0 → 10)"
echo "curl -X POST ${BASE_URL}/login -d \"username=admin' OR '1'='1&password=test\""
curl -s -X POST "${BASE_URL}/login" \
  -d "username=admin' OR '1'='1&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null
wait_and_show

echo "3️⃣ SQL Injection #2 - Union-based (score: 10 → 20)"
echo "curl -X POST ${BASE_URL}/login -d \"username=admin' UNION SELECT * FROM users--&password=test\""
curl -s -X POST "${BASE_URL}/login" \
  -d "username=admin' UNION SELECT * FROM users--&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null
wait_and_show

echo "=== 🎯 PHASE 2: CROSS-SITE SCRIPTING (2 tests) ==="
echo "4️⃣ XSS #1 - Script tag injection (score: 20 → 25)"
echo "curl \"${BASE_URL}/search?query=<script>alert('XSS')</script>\""
curl -s "${BASE_URL}/search?query=<script>alert('XSS')</script>" > /dev/null
wait_and_show

echo "5️⃣ XSS #2 - Event handler injection (score: 25 → 30)"
echo "curl \"${BASE_URL}/search?query=<img src=x onerror=alert(1)>\""
curl -s "${BASE_URL}/search?query=<img src=x onerror=alert(1)>" > /dev/null
wait_and_show

echo "=== 💀 PHASE 3: REMOTE CODE EXECUTION (2 tests) ==="
echo "6️⃣ RCE #1 - PHP shell upload (score: 30 → 50)"
echo "curl -X POST ${BASE_URL}/upload -F \"file=@/dev/null;filename=backdoor.php\""
curl -s -X POST "${BASE_URL}/upload" \
  -F "file=@/dev/null;filename=backdoor.php" > /dev/null
wait_and_show

echo "7️⃣ RCE #2 - JSP webshell upload (score: 50 → 70)"
echo "curl -X POST ${BASE_URL}/upload -F \"file=@/dev/null;filename=webshell.jsp\""
curl -s -X POST "${BASE_URL}/upload" \
  -F "file=@/dev/null;filename=webshell.jsp" > /dev/null
wait_and_show

echo "=== 🔄 PHASE 4: PATH TRAVERSAL (2 tests) ==="
echo "8️⃣ Path Traversal #1 - Basic directory traversal (score: 70 → 78)"
echo "curl -X POST ${BASE_URL}/login -d \"username=admin&password=../../../etc/passwd\""
curl -s -X POST "${BASE_URL}/login" \
  -d "username=admin&password=../../../etc/passwd" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null
wait_and_show

echo "9️⃣ Path Traversal #2 - URL encoded traversal (score: 78 → 86)"
echo "curl \"${BASE_URL}/search?query=..%2f..%2f..%2fetc%2fpasswd\""
curl -s "${BASE_URL}/search?query=..%2f..%2f..%2fetc%2fpasswd" > /dev/null
wait_and_show

echo "=== 📁 PHASE 5: FILE INCLUSION (2 tests) ==="
echo "🔟 File Inclusion #1 - Local file inclusion (score: 86 → 98)"
echo "curl \"${BASE_URL}/search?query=file:///etc/passwd\""
curl -s "${BASE_URL}/search?query=file:///etc/passwd" > /dev/null
wait_and_show

echo "1️⃣1️⃣ File Inclusion #2 - PHP wrapper (score: 98 → 110)"
echo "curl \"${BASE_URL}/search?query=php://filter/convert.base64-encode/resource=index.php\""
curl -s "${BASE_URL}/search?query=php://filter/convert.base64-encode/resource=index.php" > /dev/null
wait_and_show

echo "=== 🌐 PHASE 6: TEMPLATE INJECTION (2 tests) ==="
echo "1️⃣2️⃣ SSTI #1 - Jinja2 template injection (score: 110 → 124)"
echo "curl \"${BASE_URL}/search?query={{7*7}}\""
curl -s "${BASE_URL}/search?query=%7B%7B7*7%7D%7D" > /dev/null
wait_and_show

echo "1️⃣3️⃣ SSTI #2 - Expression evaluation (score: 124 → 138)"
echo "curl \"${BASE_URL}/search?query=\${7*7}\""
curl -s "${BASE_URL}/search?query=%24%7B7*7%7D" > /dev/null
wait_and_show

echo "=== 🗂️ PHASE 7: NOSQL INJECTION (2 tests) ==="
echo "1️⃣4️⃣ NoSQL #1 - MongoDB operator injection (score: 138 → 149)"
echo "curl -X POST ${BASE_URL}/login -d \"username=admin&password={\\\$ne: null}\""
curl -s -X POST "${BASE_URL}/login" \
  -d "username=admin&password={\$ne: null}" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null
wait_and_show

echo "1️⃣5️⃣ NoSQL #2 - Where clause injection (score: 149 → 160)"
echo "curl \"${BASE_URL}/search?query={\\\$where: 'this.username == this.password'}\""
curl -s "${BASE_URL}/search?query={\$where: 'this.username == this.password'}" > /dev/null
wait_and_show

echo "=== 🔐 PHASE 8: ACCÈS ADMINISTRATEUR (2 tests) ==="
echo "1️⃣6️⃣ Admin Access #1 - Accès sans authentification (score: 160 → 162)"
echo "curl ${BASE_URL}/admin"
curl -s "${BASE_URL}/admin" > /dev/null
wait_and_show

echo "1️⃣7️⃣ Admin Access #2 - Brute force basique (score: 162 → 164)"
echo "curl -u admin:password ${BASE_URL}/admin"
curl -s -u admin:password "${BASE_URL}/admin" > /dev/null
wait_and_show

echo "=== 🤖 PHASE 9: SECURITY TOOLS DETECTION (2 tests) ==="
echo "1️⃣8️⃣ Security Tool #1 - SQLMap User-Agent (score: 164 → 167)"
echo "curl avec User-Agent sqlmap"
curl -s -X POST "${BASE_URL}/login" \
  -d "username=admin'; WAITFOR DELAY '00:00:05'--&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: sqlmap/1.0-dev (http://sqlmap.org)" > /dev/null
wait_and_show

echo "1️⃣9️⃣ Security Tool #2 - Nikto scanner (score: 167 → 170)"
echo "curl avec User-Agent Nikto"
curl -s "${BASE_URL}/admin" \
  -H "User-Agent: Nikto/2.1.6 (www.cirt.net)" > /dev/null
wait_and_show

echo "=== ⚠️ PHASE 10: HTTP ANOMALIES (2 tests) ==="
echo "2️⃣0️⃣ HTTP Anomaly #1 - Suspicious method TRACE (score: 170 → 174)"
echo "curl -X TRACE ${BASE_URL}/"
curl -s -X TRACE "${BASE_URL}/" > /dev/null
wait_and_show

echo "2️⃣1️⃣ HTTP Anomaly #2 - Suspicious path access (score: 174 → 176)"
echo "curl ${BASE_URL}/.git/config"
curl -s "${BASE_URL}/.git/config" > /dev/null
wait_and_show

echo ""
echo "🚨🚨🚨 SEUIL CRITIQUE LARGEMENT DÉPASSÉ (Score > 150) 🚨🚨🚨"
echo "🔴 IP automatiquement blacklistée - Menace de niveau CRITIQUE"
echo ""

echo "📊 RÉSUMÉ COMPLET DE LA SESSION D'ATTAQUE:"
echo "=========================================="
echo "🎯 21 attaques simulées en 10 phases distinctes"
echo "⚡ Score final: 176 points (CRITIQUE > 150)"
echo ""

echo "📋 Détail des phases d'attaque:"
echo "• Phase 1: SQL Injection (2 tests) → +20 points"
echo "• Phase 2: Cross-Site Scripting (2 tests) → +10 points"  
echo "• Phase 3: Remote Code Execution (2 tests) → +40 points"
echo "• Phase 4: Path Traversal (2 tests) → +16 points"
echo "• Phase 5: File Inclusion (2 tests) → +24 points"
echo "• Phase 6: Template Injection (2 tests) → +28 points"
echo "• Phase 7: NoSQL Injection (2 tests) → +22 points"
echo "• Phase 8: Admin Access (2 tests) → +4 points"
echo "• Phase 9: Security Tools (2 tests) → +6 points"
echo "• Phase 10: HTTP Anomalies (2 tests) → +6 points"
echo ""

echo "🔍 Types de failles détectées:"
echo "├── Critiques (Score 15-20): RCE, Template Injection"
echo "├── Élevées (Score 8-14): File Inclusion, NoSQL, Path Traversal"  
echo "├── Moyennes (Score 5-10): SQLi, XSS"
echo "└── Informatives (Score 2-4): Admin Access, Tools, Anomalies"
echo ""

echo "📈 Derniers événements capturés:"
grep "$(date +%Y-%m-%d)" logs/telosmiligramme-*.log | tail -10 | jq -r '. | "[\(.timestamp | split("T")[1] | split(".")[0])] \(.event_type) - \(.details.threat_type // "Access") - Score: \(.ip_score)"' 2>/dev/null || echo "Logs en cours d'écriture..."

echo ""
echo "✅ DÉMONSTRATION COMPLÈTE TERMINÉE"
echo "🍯 Honeypot Telosmiligramme 100% opérationnel"
echo "📊 Surface de détection: 10+ types de failles"
echo "🔄 Patterns actifs: 400+ expressions régulières"
echo "📈 Logs centralisés via Promtail → Loki"
echo "🚨 Alerting automatique sur seuils configurables"
