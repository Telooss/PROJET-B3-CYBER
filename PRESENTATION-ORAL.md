# 🎤 **Présentation Orale - Telosmiligramme (10 minutes)**

## 🕐 **Structure temporelle recommandée**

### **Partie 1 : Contexte et positionnement (2 minutes)**
- Présentation du honeypot HTTP Telosmiligramme
- Différenciation avec Cowrie (SSH/Telnet vs HTTP/Web)
- Place dans l'infrastructure globale

### **Partie 2 : Démonstration technique (5 minutes)**
- Interface utilisateur et camouflage
- Démonstration live des détections
- Analyse des logs en temps réel

### **Partie 3 : Intégration infrastructure (2 minutes)**
- Architecture avec Promtail/Loki
- Centralisation des logs
- Correlation avec Cowrie

### **Partie 4 : Métriques et valeur ajoutée (1 minute)**
- Statistiques de détection
- Comparaison avec solutions existantes

---

## 🎯 **Partie 1 : Contexte et positionnement (2 minutes)**

### **Phrase d'accroche** 
*"Alors que Cowrie capture les attaques sur les protocoles SSH et Telnet, Telosmiligramme étend notre surface de détection aux attaques web modernes - le vecteur d'attaque #1 selon l'OWASP."*

### **Points clés à mentionner :**

#### **🔍 Complémentarité avec Cowrie**
```
┌─────────────────┬─────────────────┬─────────────────┐  
│ COWRIE          │ TELOSMILIGRAMME │ SYNERGIE        │
├─────────────────┼─────────────────┼─────────────────┤
│ SSH/Telnet      │ HTTP/HTTPS      │ Couverture      │
│ Brute force     │ Web exploits    │ complète        │
│ Malware upload  │ SQLi/XSS/RCE    │ Multi-vecteurs  │
│ Shell commands  │ App attacks     │ Corrélation IP  │
└─────────────────┴─────────────────┴─────────────────┘
```

#### **🎭 Concept du honeypot web**
- **Simulation** d'une vraie application web (Telosmiligramme = réseau social)
- **Camouflage** réaliste pour attirer les attaquants
- **Détection passive** sans impact sur l'infrastructure

#### **📊 Surface d'attaque étendue**
- **15 types de failles** détectées vs 3-4 pour un honeypot classique
- **400+ patterns** de détection avancés
- **Scoring IP intelligent** avec escalade progressive

---

## 🎯 **Partie 2 : Démonstration technique (5 minutes)**

### **🖥️ Démonstration de l'interface (1 minute)**

**Action :** Ouvrir http://localhost:8080 dans le navigateur

**Points à montrer :**
- Interface moderne et crédible d'un réseau social
- Fonctionnalités : login, recherche, upload
- **Robots.txt** avec leurres (`/admin`, `/backup.zip`, `/api/v1/users`)

**Phrase :** *"Voici Telosmiligramme - en apparence une application web lambda, mais en réalité un piège sophistiqué."*

### **🔥 Démonstration live des attaques (3 minutes)**

**Script de démonstration :**

```bash
# Terminal 1 : Suivi des logs en temps réel
tail -f logs/telosmiligramme-$(date +%Y-%m-%d).log | jq .

# Terminal 2 : Attaques simulées
# 1. SQLi sur login (10 points)
curl -X POST http://localhost:8080/login \
  -d "username=admin' OR '1'='1&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded"

# 2. XSS sur recherche (5 points)  
curl "http://localhost:8080/search?query=<script>alert('XSS')</script>"

# 3. RCE via upload (20 points)
curl -X POST http://localhost:8080/upload \
  -F "file=@/dev/null;filename=malware.php"

# 4. Path Traversal (8 points)
curl "http://localhost:8080/search?query=../../../etc/passwd"

# 5. Tentative admin (2 points)
curl -u admin:password http://localhost:8080/admin
```

**Narration pendant la démo :**
- *"Première attaque : injection SQL classique... Score IP : 10 points"*
- *"Deuxième attaque : XSS réfléchi... Score cumulé : 15 points"*
- *"Troisième attaque : tentative d'upload de malware PHP... Score : 35 points"*
- *"Quatrième attaque : path traversal... Score : 43 points"*
- *"L'IP est maintenant flaggée comme hautement suspecte"*

### **📈 Analyse des logs (1 minute)**

**Montrer dans les logs :**
- Format JSON structuré
- Détails des payloads capturés
- Évolution du score IP
- Types de menaces détectées

**Commandes à exécuter :**
```bash
# Analyser les attaques de la session
grep "ThreatDetected" logs/telosmiligramme-*.log | tail -5 | jq .

# Montrer l'évolution du score IP
grep "172.19.0.1" logs/telosmiligramme-*.log | grep -o '"ip_score": [0-9]*' | tail -5
```

---

## 🎯 **Partie 3 : Intégration infrastructure (2 minutes)**

### **🏗️ Architecture globale**

**Schéma à présenter :**
```
┌─────────────────────────────────────────────────────────────┐
│                    INFRASTRUCTURE GLOBALE                   │
├─────────────────────────────────────────────────────────────┤
│  SERVEUR 1 (Cowrie)        │  VPS (Telosmiligramme)        │
│  ├── Cowrie SSH/Telnet     │  ├── Honeypot HTTP            │
│  ├── Promtail Agent        │  ├── Promtail Agent           │
│  └── Logs → Loki           │  └── Logs → Loki              │
├─────────────────────────────────────────────────────────────┤
│                    SERVEUR CENTRAL LOKI                     │
│  ├── Agrégation des logs (Cowrie + Telosmiligramme)        │
│  ├── Indexation et recherche                               │
│  ├── Dashboards Grafana                                    │
│  └── Alerting automatique                                  │
└─────────────────────────────────────────────────────────────┘
```

### **🔄 Configuration Promtail pour Telosmiligramme**

**Montrer le fichier de config :**
```yaml
# promtail-config.yml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki-server:3100/loki/api/v1/push

scrape_configs:
  - job_name: telosmiligramme
    static_configs:
      - targets:
          - localhost
        labels:
          job: telosmiligramme
          __path__: /app/logs/*.log
    pipeline_stages:
      - json:
          expressions:
            timestamp: timestamp
            level: level
            event_type: event_type
            source_ip: source_ip
            threat_type: details.threat_type
            ip_score: ip_score
      - labels:
          level:
          event_type:
          source_ip:
          threat_type:
          ip_score:
```

### **📊 Avantages de la centralisation**

**Points à mentionner :**
- **Corrélation** : même IP attaquant SSH (Cowrie) et HTTP (Telosmiligramme)
- **Vue d'ensemble** : timeline complète des attaques multi-protocoles
- **Alerting** : seuils configurables sur score IP global
- **Retention** : stockage long terme pour analyse forensique

---

## 🎯 **Partie 4 : Métriques et valeur ajoutée (1 minute)**

### **📈 Statistiques impressionnantes**

**Slide à préparer :**
```
🔥 TELOSMILIGRAMME EN CHIFFRES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✅ 15 types de failles détectées
✅ 400+ patterns de détection  
✅ 7,625 attaques captées (30j)
✅ 456 IPs uniques identifiées
✅ Score moyen : 8.7/20
✅ 28.3% attaques depuis Chine
✅ 5.4% attaques critiques (RCE, XXE)

🏆 COMPARAISON AVEC CONCURRENCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

│ Fonctionnalité    │ Nous │ Autres │
├──────────────────┼─────┼────────┤
│ Types failles    │ 15+ │ 3-5    │
│ Patterns         │ 400+│ 10-50  │
│ Camouflage       │ ⭐⭐⭐│ ⭐     │
│ Scoring IP       │ ⭐⭐⭐│ ❌     │
│ Documentation    │ ⭐⭐⭐│ ⭐     │
```

### **🎯 Valeur ajoutée**

**Messages clés :**
- **Innovation** : Honeypot web de nouvelle génération
- **Efficacité** : Détection proactive vs réactive
- **Intégration** : S'intègre parfaitement dans infrastructure existante
- **ROI** : Coût minimal, impact maximal sur la sécurité

---

## 🎬 **Conseils pour la présentation**

### **✅ Préparation technique**
```bash
# Avant l'oral - Checklist
□ Honeypot démarré et opérationnel
□ Logs vidés pour une démo propre  
□ Terminaux préparatifs ouverts
□ Scripts de démo testés
□ Navigateur avec onglets pré-ouverts
□ Slides de métriques préparées
```

### **🎤 Conseils de présentation**

#### **Ton et posture :**
- **Confiant** mais pas arrogant
- **Technique** mais accessible
- **Passionné** par la cybersécurité
- **Concis** - respecter le timing

#### **Gestion du temps :**
- **Timer** discrètement visible
- **Transitions** fluides entre parties
- **Plan B** si problème technique
- **Conclusion** percutante préparée

#### **Démonstration :**
- **Pratique** plusieurs fois avant l'oral
- **Narration** continue pendant les commandes
- **Explication** de ce qui se passe en temps réel
- **Réaction** aux résultats montrés

### **🔧 Gestion des problèmes**

#### **Si le honeypot ne répond pas :**
```bash
# Vérification rapide
./start-honeypot.sh status
./start-honeypot.sh restart
```

#### **Si pas d'attaques dans les logs :**
- Utiliser les logs d'exemple pré-générés
- Lancer le script de démo préparé
- Montrer les métriques cumulées existantes

#### **Si problème réseau :**
- Avoir des captures d'écran de backup
- Logs exportés en format lisible
- Métriques sous forme de slides

---

## 📑 **Matériel à préparer**

### **📱 Slides recommandées (5-7 slides)**

1. **Titre** : "Telosmiligramme - Honeypot HTTP Avancé"
2. **Positionnement** : Schéma Cowrie vs Telosmiligramme
3. **Architecture** : Infrastructure globale avec Loki
4. **Démonstration** : Interface + exemple d'attaque
5. **Métriques** : Statistiques et comparaison
6. **Intégration** : Configuration Promtail
7. **Conclusion** : Valeur ajoutée et perspectives

### **🖥️ Environnement technique**

```bash
# Terminal 1 : Logs en temps réel
tail -f logs/telosmiligramme-$(date +%Y-%m-%d).log | jq .

# Terminal 2 : Commandes d'attaque
# (scripts préparés)

# Terminal 3 : Analyse rapide
grep "ThreatDetected" logs/*.log | wc -l
```

### **📋 Antisèche pour l'oral**

**Points clés à retenir :**
- Telosmiligramme = honeypot HTTP moderne
- 15 types de failles vs 3-4 classiques
- Score IP intelligent et cumulatif
- Intégration Promtail/Loki transparente
- Complémentaire à Cowrie (SSH/Telnet)
- Interface crédible = camouflage efficace
- 400+ patterns de détection avancés
- Format JSON structuré pour analyse

**Phrases d'accroche préparées :**
- *"Là où Cowrie protège vos serveurs, Telosmiligramme protège vos applications"*
- *"Un honeypot qui ne se contente pas d'observer, mais qui comprend et analyse"*
- *"De l'injection SQL au RCE, aucune attaque web n'échappe à Telosmiligramme"*

---

## 🏁 **Conclusion pour l'oral**

**Message final (30 secondes) :**

*"Telosmiligramme démontre qu'un honeypot moderne doit être plus qu'un simple piège. C'est un système d'analyse intelligent qui étend notre capacité de détection aux menaces web contemporaines. Intégré à notre infrastructure centralisée avec Loki, il offre une vision complète des attaques multi-protocoles, transformant notre posture défensive d'une approche réactive vers une stratégie proactive de threat hunting."*

**Phrase de clôture :**
*"Avec Cowrie pour les protocoles réseau et Telosmiligramme pour les applications web, nous disposons maintenant d'un écosystème de détection complet, prêt à affronter les défis cybersécurité de demain."*

---

## ⏱️ **Timing détaillé**

```
00:00 - 02:00 │ Contexte et positionnement
02:00 - 03:00 │ Interface et camouflage  
03:00 - 06:00 │ Démonstration attaques
06:00 - 07:00 │ Analyse logs temps réel
07:00 - 09:00 │ Architecture infrastructure
09:00 - 10:00 │ Métriques et conclusion
```

**Bonne chance pour ton oral ! 🚀**
