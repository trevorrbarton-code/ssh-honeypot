# SSH Honeypot Project Summary

## Overview

This is a comprehensive medium-interaction SSH honeypot built with Python, featuring machine learning-based bot detection, real-time analytics dashboard, and automated reporting.

## Project Structure

```
ssh-honeypot/
├── honeypot/                   # Core honeypot implementation
│   ├── __init__.py            # Package initialization
│   ├── ssh_server.py          # SSH server using Paramiko
│   ├── shell.py               # Fake bash shell with 100+ commands
│   ├── filesystem.py          # Simulated Debian filesystem
│   └── database.py            # SQLite logging and analytics
│
├── ml/                         # Machine learning module
│   ├── __init__.py
│   └── keystroke_classifier.py # Human vs bot classification
│
├── dashboard/                  # Flask web dashboard
│   ├── app.py                 # Flask application with REST API
│   └── templates/
│       └── index.html         # Real-time analytics UI
│
├── reports/                    # Report generation
│   ├── __init__.py
│   └── daily_report.py        # Daily attacker psychology reports
│
├── config/                     # Configuration files
│   └── honeypot.conf          # Main configuration
│
├── data/                       # Persistent data (SQLite DB)
├── logs/                       # Log files
├── reports/                    # Generated reports
│
├── Dockerfile                  # Docker image definition
├── docker-compose.yml          # Multi-service orchestration
├── requirements.txt            # Python dependencies
├── .env.example               # Environment template
├── start.sh                   # Startup script
├── Makefile                   # Management commands
├── README.md                  # Comprehensive documentation
├── LICENSE                    # MIT License
└── .gitignore                 # Git ignore rules
```

## Key Features Implemented

### 1. SSH Honeypot Core (`honeypot/ssh_server.py`)
- Full SSH server implementation using Paramiko
- Realistic Debian SSH banners
- Credential logging (all auth attempts)
- Session management with unique IDs
- Keystroke timing capture for ML analysis
- Multi-threaded connection handling

### 2. Fake Filesystem (`honeypot/filesystem.py`)
- Complete Debian directory structure
- Realistic system files:
  - /etc/passwd, /etc/shadow with fake hashes
  - /etc/os-release, /etc/hosts, /etc/hostname
  - /proc/cpuinfo, /proc/meminfo, /proc/uptime
  - /var/log/auth.log, /var/log/syslog
- File permissions and ownership simulation
- Directory navigation (cd, ls, pwd)

### 3. Fake Shell (`honeypot/shell.py`)
- 100+ implemented commands:
  - System info: uname, whoami, id, w, last, ps
  - Network: ifconfig, netstat, ping, curl, wget
  - File operations: cat, ls, grep, find, head, tail
  - Package management: apt-get (simulated)
  - Docker/Kubernetes commands
  - Database clients: mysql, psql, mongo, redis-cli
- Command analysis and TTP detection
- Suspicious pattern recognition
- Command history tracking

### 4. Database (`honeypot/database.py`)
- SQLite with thread-local connections
- Tables:
  - `sessions`: Session metadata, classification, geo data
  - `auth_attempts`: Authentication attempts
  - `commands`: Command execution log with analysis
  - `keystroke_timings`: Individual keystroke intervals
  - `ttps`: Tactics, Techniques, Procedures
  - `daily_stats`: Aggregated daily statistics
- Indexes for performance
- JSON field support for complex data

### 5. ML Classifier (`ml/keystroke_classifier.py`)
- **30+ Features Extracted**:
  - Timing statistics (mean, std, median, percentiles)
  - Fast/slow keystroke ratios
  - Coefficient of variation
  - Skewness and kurtosis
  - Autocorrelation patterns
  - Burst detection
  - Trend analysis
- **Classification Algorithm**: Random Forest
- **Synthetic Training Data**: Generates realistic human/bot patterns
- **Real-time Classification**: Confidence scores and indicators
- **Feature Importance**: Identifies key distinguishing factors

**Classification Logic**:
- Bots: Consistent timing (<50ms), low variance, predictable
- Humans: Variable timing (50-500ms), natural bursts, high variance

### 6. Dashboard (`dashboard/app.py`, `templates/index.html`)
- **Real-time Updates**: WebSocket for live data
- **Visualizations**:
  - Attack distribution (human vs bot)
  - Geographic heatmap (Leaflet.js)
  - Command frequency charts
  - TTP analysis
  - Classification confidence
- **REST API Endpoints**:
  - `/api/stats` - Attack statistics
  - `/api/sessions` - Recent sessions
  - `/api/geolocation` - Attack origins
  - `/api/commands/frequency` - Command analysis
  - `/api/classification/realtime` - Classification data
  - `/api/ttps` - TTP summary
  - `/api/classifier/train` - Train ML model

### 7. Daily Reports (`reports/daily_report.py`)
- **Attacker Psychology Analysis**:
  - Behavioral pattern recognition
  - Geographic concentration analysis
  - TTP sophistication assessment
  - Command sequence analysis
  - Session duration patterns
- **Insights Generation**:
  - Human vs bot ratio implications
  - Geographic attack patterns
  - Advanced persistent threat indicators
  - Weak password attack detection
  - Repetitive attack patterns
- **Output Formats**: HTML (rich) and text (simple)

### 8. Docker Configuration
- **Multi-service Setup**:
  - `honeypot`: SSH server (port 2222)
  - `dashboard`: Web UI (port 8080)
  - `report-generator`: Scheduled reports
- **Network Isolation**:
  - `honeypot_isolated`: No outbound access
  - `honeypot_monitoring`: Internal monitoring
  - `dashboard_external`: External access only
- **Security Features**:
  - Non-root user execution
  - Read-only root filesystem
  - Resource limits (CPU, memory)
  - Capability dropping
  - Security options (no-new-privileges)

## Technical Specifications

### Dependencies
```
paramiko==3.4.0      # SSH protocol
flask==3.0.0         # Web framework
scikit-learn==1.3.0  # Machine learning
numpy==1.24.0        # Numerical computing
pandas==2.0.0        # Data analysis
plotly==5.18.0       # Visualizations
geoip2==4.7.0        # Geolocation
```

### Database Schema
```sql
-- Sessions table with ML classification
CREATE TABLE sessions (
    session_id TEXT UNIQUE,
    client_ip TEXT,
    username TEXT,
    classified_as TEXT,  -- 'human' or 'bot'
    classification_confidence REAL,
    keystroke_data TEXT, -- JSON array
    geo_country TEXT,
    geo_latitude REAL,
    geo_longitude REAL
);

-- Commands with TTP analysis
CREATE TABLE commands (
    session_id TEXT,
    command TEXT,
    suspicious BOOLEAN,
    patterns_detected TEXT, -- JSON array
    intent_classification TEXT,
    severity TEXT
);
```

### ML Model Performance
- **Algorithm**: Random Forest (100 estimators)
- **Features**: 30 keystroke timing features
- **Training**: Synthetic data (2000 samples)
- **Validation**: 5-fold cross-validation
- **Expected Accuracy**: 90-95% on synthetic data

## Usage Examples

### Start the Honeypot
```bash
# Quick start
./start.sh

# Or with make
make setup
make start

# Or with Docker Compose directly
docker-compose up -d
```

### Access Dashboard
```
http://localhost:8080
```

### Train ML Classifier
```bash
# Via API
curl -X POST http://localhost:8080/api/classifier/train

# Via Make
make train
```

### Generate Report
```bash
# Manual generation
make report

# Or via Docker
docker-compose run --rm report-generator
```

### View Logs
```bash
# All logs
make logs

# Honeypot only
make logs-hp

# Dashboard only
make logs-db
```

## Security Considerations

### Network Isolation
- Honeypot container has no outbound internet access
- Dashboard on separate network segment
- Internal networks isolated from external

### Resource Limits
- CPU: 0.5 cores per container
- Memory: 512MB per container
- Read-only filesystem
- Dropped Linux capabilities

### Data Protection
- SQLite database in isolated volume
- Logs rotated automatically
- Sensitive data not logged in plain text

## Ethical Deployment Checklist

- [ ] Own the network or have written authorization
- [ ] Understand local laws on data collection
- [ ] Network isolated from production systems
- [ ] Monitoring and incident response in place
- [ ] Data retention policy defined
- [ ] Legal review completed

## Future Enhancements

1. **Enhanced ML**:
   - Deep learning models (LSTM for sequence analysis)
   - Unsupervised anomaly detection
   - Transfer learning from other honeypots

2. **Additional Protocols**:
   - Telnet honeypot
   - FTP honeypot
   - HTTP/HTTPS honeypot

3. **Integration**:
   - SIEM integration (Splunk, ELK)
   - Threat intelligence feeds
   - Automated blocking (fail2ban)

4. **Advanced Analytics**:
   - Attack campaign clustering
   - Attacker attribution
   - Predictive threat modeling

## License

MIT License - See LICENSE file

**Disclaimer**: This software is for educational and research purposes only. Users are responsible for legal and ethical deployment.
