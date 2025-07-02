# HTTP Honeypot - Docker Deployment

Ce guide vous aide à déployer facilement le honeypot HTTP en utilisant Docker.

## Prérequis

- Docker (version 20.10 ou plus récente)
- Docker Compose (version >=2.0 ou docker-compose >=1.29)
- 512 MB de RAM disponible
- Port 8080 libre

## Installation rapide

### Option 1: Script automatique (Recommandée)

```bash
# Rendre le script exécutable
chmod +x start-honeypot.sh

# Construire et démarrer le honeypot
./start-honeypot.sh build
./start-honeypot.sh start
```

### Option 2: Docker Compose manuel

```bash
# Construire l'image
docker-compose build

# Démarrer le honeypot
docker-compose up -d

# Voir les logs
docker-compose logs -f honeypot
```

### Option 3: Docker simple

```bash
# Construire l'image
docker build -t http-honeypot .

# Démarrer le conteneur
docker run -d \
  --name http-honeypot \
  -p 8080:8080 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/honeypot.log:/app/honeypot.log \
  http-honeypot
```

## Utilisation du script de gestion

Le script `start-honeypot.sh` facilite la gestion du honeypot :

```bash
./start-honeypot.sh build     # Construire l'image Docker
./start-honeypot.sh start     # Démarrer le honeypot
./start-honeypot.sh stop      # Arrêter le honeypot
./start-honeypot.sh restart   # Redémarrer le honeypot
./start-honeypot.sh logs      # Voir les logs
./start-honeypot.sh logs -f   # Suivre les logs en temps réel
./start-honeypot.sh status    # Voir le statut du conteneur
./start-honeypot.sh clean     # Nettoyer les ressources Docker
./start-honeypot.sh help      # Afficher l'aide
```

## Accès au honeypot

Une fois démarré, le honeypot est accessible sur :
- **URL principale** : http://localhost:8080
- **Page de connexion** : http://localhost:8080/login
- **Page de recherche** : http://localhost:8080/search
- **Page d'upload** : http://localhost:8080/upload
- **Robots.txt** : http://localhost:8080/robots.txt

## Surveillance des logs

### Logs en temps réel
```bash
./start-honeypot.sh logs -f
```

### Logs dans le fichier
```bash
tail -f honeypot.log
```

### Format des logs
Les logs sont au format JSON et contiennent :
- Timestamp UTC
- Adresse IP source
- Méthode HTTP et chemin
- Headers de la requête
- Corps de la requête
- Score de l'IP (scoring des tentatives d'attaque)

Exemple de log :
```json
{
  "timestamp": "2025-07-01T10:30:45.123456",
  "level": "INFO",
  "event_type": "http_request",
  "source_ip": "192.168.1.100",
  "request": {
    "method": "POST",
    "path": "/login",
    "headers": {...},
    "args": {...},
    "body": "username=admin&password=123456"
  },
  "details": "Login attempt detected",
  "ip_score": 10
}
```

## Configuration

### Variables d'environnement

Vous pouvez modifier les variables dans `docker-compose.yml` :

```yaml
environment:
  - BACKEND_PORT=8080        # Port du serveur Flask
  - FLASK_ENV=production     # Mode Flask
```

### Limites de ressources

Par défaut, le conteneur est limité à :
- CPU : 0.5 core maximum, 0.25 core réservé
- RAM : 512MB maximum, 256MB réservé

### Persistance des données

Les logs sont automatiquement persistés :
- `./logs/` : Dossier pour les logs additionnels
- `./honeypot.log` : Fichier principal des logs

## Sécurité

### Mesures de sécurité intégrées

- Conteneur en mode lecture seule partielle
- Pas de nouveaux privilèges (`no-new-privileges`)
- Limitation des ressources système
- Logs rotatifs automatiques
- Isolation réseau

### Recommandations de déploiement

1. **Firewall** : Utilisez un firewall pour contrôler l'accès
2. **Proxy inverse** : Déployez derrière nginx ou Apache
3. **Monitoring** : Surveillez les ressources système
4. **Sauvegarde** : Sauvegardez régulièrement les logs

## Dépannage

### Le conteneur ne démarre pas
```bash
# Vérifier les logs d'erreur
docker-compose logs honeypot

# Vérifier l'état du conteneur
docker-compose ps
```

### Port déjà utilisé
```bash
# Trouver quel processus utilise le port 8080
sudo netstat -tulpn | grep :8080

# Ou utiliser ss
sudo ss -tulpn | grep :8080
```

### Problèmes de permissions
```bash
# S'assurer que les dossiers sont accessibles
chmod 755 logs/
chmod 666 honeypot.log
```

### Nettoyage complet
```bash
# Arrêter et supprimer complètement
docker-compose down -v
docker system prune -a
```

## Intégration avec des outils d'analyse

### ELK Stack (Elasticsearch, Logstash, Kibana)

```bash
# Exemple de configuration Logstash pour parser les logs JSON
input {
  file {
    path => "/path/to/honeypot.log"
    start_position => "beginning"
    codec => "json"
  }
}

filter {
  date {
    match => [ "timestamp", "ISO8601" ]
  }
  
  geoip {
    source => "source_ip"
    target => "geoip"
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "honeypot-logs-%{+YYYY.MM.dd}"
  }
}
```

### Prometheus + Grafana

Les métriques Docker peuvent être exportées vers Prometheus pour monitoring.

## Développement

### Reconstruction après modifications
```bash
./start-honeypot.sh stop
./start-honeypot.sh build
./start-honeypot.sh start
```

### Debug mode
```bash
# Démarrer en mode interactif pour debug
docker-compose run --rm honeypot /bin/bash
```

## Support

Pour toute question ou problème :
1. Vérifiez les logs : `./start-honeypot.sh logs`
2. Vérifiez le statut : `./start-honeypot.sh status`
3. Consultez la documentation Docker
4. Redémarrez le service : `./start-honeypot.sh restart`
