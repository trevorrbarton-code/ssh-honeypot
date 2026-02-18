# SSH Honeypot with ML-Powered Bot Detection

A medium-interaction SSH honeypot built with Python and Paramiko, featuring a realistic Debian environment, keystroke dynamics analysis for human vs bot classification, and comprehensive analytics dashboard.

## ⚠️ ETHICAL WARNINGS & LEGAL CONSIDERATIONS

**READ THIS SECTION CAREFULLY BEFORE DEPLOYMENT**

### Purpose
This honeypot is designed for:
- Security research and education
- Threat intelligence gathering
- Understanding attacker methodologies
- Network defense improvement

### Legal Requirements

1. **Authorization**: Only deploy on systems you own or have explicit written authorization to monitor.

2. **Jurisdiction**: Ensure honeypot deployment complies with local laws regarding:
   - Data collection and privacy
   - Interception of communications
   - Computer fraud and abuse statutes

3. **Data Handling**: 
   - Collected data may contain personal information
   - Implement appropriate data retention policies
   - Secure stored data appropriately

4. **No Entrapment**: This tool should not be used to entrap or incite illegal activity.

### Security Considerations

1. **Network Isolation**: Always deploy in isolated network segments. The Docker Compose configuration includes network isolation, but verify your network setup.

2. **Resource Limits**: The honeypot includes resource limits, but monitor for denial-of-service attacks.

3. **Egress Filtering**: Ensure the honeypot cannot be used as a launch point for attacks against third parties.

4. **Monitoring**: Maintain logs of honeypot access for audit purposes.

**By using this software, you acknowledge full responsibility for its deployment and use.**

---

## Features

### Core Honeypot
- **Realistic Debian Environment**: Complete fake filesystem with common Linux files, directories, and command outputs
- **SSH Protocol Support**: Full SSH server implementation using Paramiko
- **Credential Logging**: Captures all authentication attempts (username/password)
- **Command Logging**: Records all executed commands with timestamps
- **Session Management**: Tracks session duration, keystroke dynamics, and user behavior

### Machine Learning Classification
- **Keystroke Dynamics Analysis**: Distinguishes between human attackers and automated bots
- **Feature Extraction**: Analyzes 30+ features including timing patterns, burst detection, and distribution statistics
- **Real-time Classification**: Classifies sessions with confidence scores
- **Continuous Learning**: Model can be retrained with feedback

**Classification Methodology:**
- **Bots**: Consistent timing (<50ms), low variance, predictable patterns
- **Humans**: Variable timing (50-500ms), natural typing bursts, higher variance

### Analytics Dashboard
- **Real-time Monitoring**: Live updates via WebSocket
- **Attack Origin Heatmap**: Geographic visualization of attack sources
- **Command Frequency Analysis**: Most common commands and categories
- **Human vs Bot Classification**: Visual breakdown with confidence scores
- **Session Details**: Deep dive into individual attack sessions
- **TTP Analysis**: Tactics, Techniques, and Procedures tracking

### Daily Reports
- **Attacker Psychology Report**: Automated daily analysis of attacker behavior
- **Pattern Recognition**: Identifies attack campaigns and trends
- **Recommendations**: Security recommendations based on observed TTPs
- **Multiple Formats**: HTML and text report generation

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SSH Honeypot System                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   SSH Server │    │   Fake Shell │    │   Fake FS    │  │
│  │   (Paramiko) │───▶│   (Bash-like)│───▶│   (Debian)   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                   │                               │
│         ▼                   ▼                               │
│  ┌──────────────────────────────────┐                      │
│  │         SQLite Database          │                      │
│  │  (Sessions, Commands, Keystrokes)│                      │
│  └──────────────────────────────────┘                      │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────────────────────────┐                      │
│  │    ML Classifier (scikit-learn) │                      │
│  │     (Human vs Bot Detection)    │                      │
│  └──────────────────────────────────┘                      │
│         │                                                   │
│         ▼                                                   │
│  ┌──────────────────────────────────┐                      │
│  │      Flask Dashboard             │                      │
│  │  (Analytics & Visualization)     │                      │
│  └──────────────────────────────────┘                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- 2GB RAM minimum
- 10GB disk space

### Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd ssh-honeypot
```

2. **Configure environment**:
```bash
cp .env.example .env
# Edit .env with your settings
```

3. **Create directories**:
```bash
mkdir -p data logs reports config
```

4. **Start the honeypot**:
```bash
docker-compose up -d
```

5. **Access the dashboard**:
```
http://localhost:8080
```

### Default Ports
- SSH Honeypot: `2222` (external) → `2222` (internal)
- Dashboard: `8080` (external) → `8080` (internal)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEYPOT_EXTERNAL_PORT` | 2222 | External SSH port |
| `DASHBOARD_EXTERNAL_PORT` | 8080 | External dashboard port |
| `FLASK_SECRET_KEY` | - | Secret key for Flask sessions |
| `LOG_LEVEL` | INFO | Logging level |
| `DATA_DIR` | ./data | Database storage directory |
| `LOGS_DIR` | ./logs | Log files directory |
| `REPORTS_DIR` | ./reports | Report output directory |

### Customizing the Fake Environment

Edit `honeypot/filesystem.py` to customize:
- Fake file contents
- Directory structures
- System information (hostname, users, etc.)

### Adding Custom Commands

Edit `honeypot/shell.py` to add or modify:
- Command handlers
- Output formats
- Suspicious pattern detection

## Usage

### Monitoring Attacks

1. **Dashboard Overview**:
   - Real-time statistics
   - Recent sessions
   - Attack classification

2. **Attack Map**:
   - Geographic origin visualization
   - Country/city breakdown

3. **Command Analysis**:
   - Most frequent commands
   - Command categories
   - Suspicious activity

4. **Session Details**:
   - Complete command history
   - Keystroke timing analysis
   - Classification confidence

### Training the Classifier

The classifier is automatically trained on startup with synthetic data. To retrain:

```bash
# Via API
curl -X POST http://localhost:8080/api/classifier/train

# Via dashboard
Navigate to "ML Model" tab → Click "Train Model"
```

### Generating Reports

**Manual generation**:
```bash
docker-compose run --rm report-generator
```

**Automated (cron)**:
```bash
# Add to crontab for daily reports at 00:00
0 0 * * * cd /path/to/ssh-honeypot && docker-compose run --rm report-generator
```

Reports are saved to `./reports/` in HTML and text formats.

## Security Hardening

### Network Isolation

The Docker Compose configuration includes:
- Isolated internal networks
- No outbound internet access for honeypot
- Separate network for dashboard access

### Resource Limits

Default limits per container:
- CPU: 0.5 cores
- Memory: 512MB
- Read-only root filesystem
- Dropped capabilities

### Additional Hardening

1. **Firewall Rules**:
```bash
# Allow only specific IPs to access dashboard
iptables -A INPUT -p tcp --dport 8080 -s YOUR_IP -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j DROP
```

2. **Fail2ban Integration**:
```bash
# Monitor honeypot logs for repeated attacks
# Configure fail2ban to block aggressive scanners
```

3. **Log Rotation**:
```bash
# Configure logrotate for honeypot logs
/etc/logrotate.d/honeypot
```

## API Reference

### REST Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Get attack statistics |
| `/api/sessions` | GET | List recent sessions |
| `/api/session/<id>/commands` | GET | Get session commands |
| `/api/geolocation` | GET | Get attack geolocation data |
| `/api/commands/frequency` | GET | Get command frequency |
| `/api/classification/realtime` | GET | Get classification data |
| `/api/classifier/train` | POST | Train/retrain classifier |
| `/api/ttps` | GET | Get TTPs summary |
| `/api/daily-stats` | GET | Get daily statistics |

### WebSocket Events

| Event | Description |
|-------|-------------|
| `stats_update` | Real-time statistics update |
| `connect` | Client connected |
| `disconnect` | Client disconnected |

## Troubleshooting

### Common Issues

1. **Port already in use**:
```bash
# Change ports in .env
HONEYPOT_EXTERNAL_PORT=2223
DASHBOARD_EXTERNAL_PORT=8081
```

2. **Permission denied**:
```bash
# Fix directory permissions
sudo chown -R $USER:$USER data logs reports
```

3. **Database locked**:
```bash
# Restart services
docker-compose restart
```

### Logs

```bash
# View honeypot logs
docker-compose logs -f honeypot

# View dashboard logs
docker-compose logs -f dashboard

# View all logs
docker-compose logs -f
```

## Development

### Project Structure

```
ssh-honeypot/
├── honeypot/           # Core honeypot code
│   ├── ssh_server.py   # SSH server implementation
│   ├── shell.py        # Fake shell
│   ├── filesystem.py   # Fake filesystem
│   └── database.py     # Database handler
├── ml/                 # Machine learning
│   └── keystroke_classifier.py
├── dashboard/          # Flask dashboard
│   ├── app.py
│   └── templates/
├── reports/            # Report generation
│   └── daily_report.py
├── config/             # Configuration files
├── data/               # Database storage
├── logs/               # Log files
├── reports/            # Generated reports
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

### Running Tests

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - See LICENSE file for details

**IMPORTANT**: This software is provided for educational and research purposes only. The authors assume no liability for misuse or damage caused by this software.

## Acknowledgments

- Paramiko library for SSH protocol implementation
- scikit-learn for machine learning capabilities
- Flask and SocketIO for real-time dashboard
- MITRE ATT&CK framework for TTP classification

## Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Honeynet Project](https://www.honeynet.org/)
- [Paramiko Documentation](http://www.paramiko.org/)

## Contact

For questions, issues, or contributions, please open an issue on the repository.

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
