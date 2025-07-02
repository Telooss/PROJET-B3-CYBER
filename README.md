# 🍯 Telosmiligramme - HTTP Honeypot

[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://docker.com)
[![Python](https://img.shields.io/badge/Python-3.12-green.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-red.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight, educational HTTP honeypot designed to simulate a social media platform called "Telosmiligramme". This project demonstrates web application security concepts and helps understand common attack patterns.

## 🎯 Features

- **Realistic Web Interface**: Mimics a modern social media platform
- **Attack Detection**: Logs and analyzes suspicious activities
- **IP Scoring System**: Tracks and scores malicious IPs
- **Persistent JSON Logging**: Structured logging with host persistence for monitoring integration
- **Docker Support**: Easy deployment with Docker
- **Security Hardened**: Non-root container execution
- **Health Monitoring**: Built-in health checks
- **Loki-Ready**: Log format optimized for future Grafana Loki integration

## 📊 Log Persistence

The honeypot logs are **automatically persisted** on the host machine:
- `./telosmiligramme.log` - Main log file with all events
- `./logs/` - Additional log directory for future extensions

Logs remain accessible even after container restarts, making them ready for integration with monitoring systems like Grafana Loki, ELK Stack, or similar log aggregation platforms.

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- 512 MB RAM minimum
- Port 8080 available

### Option 1: Using the Management Script (Recommended)

```bash
# Clone the repository
git clone <your-repo-url>
cd PROJET-B3-CYBER

# Make the script executable
chmod +x start-telosmiligramme.sh

# Build and start the honeypot
./start-telosmiligramme.sh build
./start-telosmiligramme.sh start
```

### Option 2: Docker Compose

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f telosmiligramme
```

### Option 3: Pure Docker

```bash
# Build the image
docker build -t http-telosmiligramme .

# Run the container
docker run -d \
  --name http-telosmiligramme \
  -p 8080:8080 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/telosmiligramme.log:/app/telosmiligramme.log \
  http-telosmiligramme
```

## 🌐 Accessing the Honeypot

Once running, access the honeypot at:
- **Main site**: http://localhost:8080
- **Login page**: http://localhost:8080/login
- **Search page**: http://localhost:8080/search
- **Upload page**: http://localhost:8080/upload

## 📊 Monitoring

### View Live Logs
```bash
./start-telosmiligramme.sh logs -f
```

### Check Status
```bash
./start-telosmiligramme.sh status
```

### Example Log Entry
```json
{
  "timestamp": "2025-07-01T15:30:45.123456",
  "level": "INFO",
  "event_type": "login_attempt",
  "source_ip": "192.168.1.100",
  "request": {
    "method": "POST",
    "path": "/login",
    "headers": {...},
    "body": "username=admin&password=123456"
  },
  "details": "Failed login attempt",
  "ip_score": 15
}
```

## 🛠️ Management Commands

The `start-telosmiligramme.sh` script provides easy management:

```bash
./start-telosmiligramme.sh build     # Build the Docker image
./start-telosmiligramme.sh start     # Start the telosmiligramme server
./start-telosmiligramme.sh stop      # Stop the telosmiligramme server
./start-telosmiligramme.sh restart   # Restart the telosmiligramme server
./start-telosmiligramme.sh logs      # View logs
./start-telosmiligramme.sh logs -f   # Follow logs in real-time
./start-telosmiligramme.sh status    # Show container status
./start-telosmiligramme.sh clean     # Clean up Docker resources
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file to customize settings:

```bash
# Server configuration
BACKEND_PORT=8080
FLASK_ENV=production

# Logging configuration
LOG_LEVEL=INFO
```

### Resource Limits

Default limits (configurable in `docker-compose.yml`):
- CPU: 0.5 cores max, 0.25 cores reserved
- Memory: 512MB max, 256MB reserved

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Attackers     │───▶│  Telosmiligramme │───▶│   Log Analysis  │
│                 │    │   (Flask App)    │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                               │
                               ▼
                       ┌──────────────────┐
                       │   Docker Host    │
                       │   (Isolated)     │
                       └──────────────────┘
```

### Key Components

- **Flask Backend**: Serves the honeypot interface
- **Static Assets**: Pre-built Next.js frontend
- **Logging System**: JSON-structured event logging
- **IP Scoring**: Behavioral analysis of visitors
- **Docker Container**: Isolated execution environment

## 🔒 Security Features

- **Non-root execution**: Container runs as unprivileged user
- **Resource limits**: Prevents resource exhaustion
- **Network isolation**: Containerized environment
- **Read-only filesystem**: Minimal write permissions
- **Health checks**: Automatic service monitoring

## 📝 Development

### Project Structure

```
PROJET-B3-CYBER/
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container definition
├── docker-compose.yml          # Multi-container setup
├── start-telosmiligramme.sh    # Management script
├── templates/                  # HTML templates
├── static/                     # Static assets (CSS, JS, images)
├── public/                     # Public assets
└── logs/                       # Log files directory
```

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
python app.py
```

## 📋 Logs Analysis

### Common Attack Patterns

The honeypot detects and logs:
- SQL injection attempts
- XSS attacks
- Directory traversal
- Brute force login attempts
- Bot scanning activities

### Integration with SIEM

Logs are JSON formatted for easy integration with:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Splunk
- Prometheus + Grafana
- Custom log analysis tools

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY**

This honeypot is designed for:
- Cybersecurity education
- Attack pattern research
- Security awareness training
- Controlled security testing

**NOT for production use or as a replacement for proper security measures.**

## 📚 Educational Use

This project demonstrates:
- Web application honeypot concepts
- Attack detection and logging
- Containerized security applications
- DevOps and Docker best practices

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Flask framework for the web application
- Docker for containerization
- Python community for excellent libraries

---
*Dernière mise à jour : 2 juillet 2025*
