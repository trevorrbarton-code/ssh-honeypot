#!/usr/bin/env python3
"""
Daily Attacker Psychology Report Generator
Analyzes TTPs and generates insights about attacker behavior
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import Counter, defaultdict
import jinja2

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.database import HoneypotDatabase

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AttackerPsychologyReport:
    """Generate daily reports on attacker psychology and TTPs"""
    
    # TTP descriptions for report
    TTP_DESCRIPTIONS = {
        'reconnaissance': {
            'description': 'Information gathering and system profiling',
            'indicators': ['uname', 'whoami', 'id', 'ps', 'netstat', 'ifconfig', 'cat /etc/', 'cat /proc/'],
            'psychology': 'Attackers are mapping the environment to understand what they\'ve compromised.',
            'sophistication': 'low'
        },
        'privilege_escalation': {
            'description': 'Attempts to gain higher-level permissions',
            'indicators': ['sudo', 'su', 'passwd', 'chmod', 'chown', 'useradd'],
            'psychology': 'Attackers seeking root access for complete system control.',
            'sophistication': 'medium'
        },
        'persistence': {
            'description': 'Establishing backdoors for continued access',
            'indicators': ['crontab', 'echo >>', 'systemctl', 'service', '.bashrc', 'ssh key'],
            'psychology': 'Long-term thinking - attackers want to maintain access even if discovered.',
            'sophistication': 'high'
        },
        'reverse_shell': {
            'description': 'Setting up outbound connections for remote control',
            'indicators': ['nc -e', 'ncat -e', 'bash -i', 'python socket', 'mkfifo', 'backpipe'],
            'psychology': 'Bypassing firewalls by initiating outbound connections to attacker C2.',
            'sophistication': 'high'
        },
        'cryptomining': {
            'description': 'Deploying cryptocurrency mining malware',
            'indicators': ['minerd', 'xmrig', 'stratum', 'mining pool'],
            'psychology': 'Financial motivation - monetizing compromised resources immediately.',
            'sophistication': 'medium'
        },
        'data_exfiltration': {
            'description': 'Stealing data from the system',
            'indicators': ['scp', 'rsync', 'curl -d', 'wget -O', 'tar', 'zip'],
            'psychology': 'Targeted attack - seeking specific valuable information.',
            'sophistication': 'high'
        },
        'destructive': {
            'description': 'Causing damage or disruption',
            'indicators': ['rm -rf /', 'dd if=/dev/zero', 'mkfs', 'fdisk'],
            'psychology': 'Sabotage or covering tracks - often state-sponsored or hacktivist.',
            'sophistication': 'low'
        },
        'download_execute': {
            'description': 'Downloading and executing payloads',
            'indicators': ['curl | bash', 'wget | bash', 'base64 -d', 'eval'],
            'psychology': 'Rapid deployment - part of automated attack chains or botnets.',
            'sophistication': 'medium'
        },
        'network_scanning': {
            'description': 'Scanning network for other targets',
            'indicators': ['nmap', 'ping sweep', 'netdiscover'],
            'psychology': 'Lateral movement preparation - expanding foothold in network.',
            'sophistication': 'medium'
        },
        'credential_harvesting': {
            'description': 'Stealing passwords and credentials',
            'indicators': ['cat /etc/shadow', 'cat /etc/passwd', '.bash_history', 'ssh keys'],
            'psychology': 'Seeking credentials for lateral movement or sale on dark web.',
            'sophistication': 'medium'
        }
    }
    
    def __init__(self, db: HoneypotDatabase):
        self.db = db
        self.report_date = datetime.now() - timedelta(days=1)
        
    def generate_report(self, output_format: str = 'html') -> str:
        """Generate the daily report"""
        logger.info(f"Generating report for {self.report_date.date()}")
        
        # Gather data
        data = self._gather_data()
        
        # Analyze patterns
        analysis = self._analyze_patterns(data)
        
        # Generate insights
        insights = self._generate_insights(data, analysis)
        
        # Create report
        if output_format == 'html':
            return self._generate_html_report(data, analysis, insights)
        else:
            return self._generate_text_report(data, analysis, insights)
    
    def _gather_data(self) -> Dict:
        """Gather data for the report period"""
        start_time = self.report_date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(days=1)
        
        # Get sessions
        sessions = self.db.get_recent_sessions(limit=1000)
        
        # Filter for report period
        day_sessions = []
        for s in sessions:
            session_time = s['start_time']
            if isinstance(session_time, str):
                session_time = datetime.fromisoformat(session_time.replace('Z', '+00:00'))
            if start_time <= session_time < end_time:
                day_sessions.append(s)
        
        # Get all commands for these sessions
        all_commands = []
        for session in day_sessions:
            commands = self.db.get_session_commands(session['session_id'])
            all_commands.extend(commands)
        
        # Get TTPs
        ttps = self.db.get_ttps_summary(days=1)
        
        # Get classifications
        human_count = sum(1 for s in day_sessions if s.get('classified_as') == 'human')
        bot_count = sum(1 for s in day_sessions if s.get('classified_as') == 'bot')
        
        return {
            'date': self.report_date.date(),
            'sessions': day_sessions,
            'commands': all_commands,
            'ttps': ttps,
            'human_count': human_count,
            'bot_count': bot_count,
            'total_sessions': len(day_sessions),
            'total_commands': len(all_commands)
        }
    
    def _analyze_patterns(self, data: Dict) -> Dict:
        """Analyze attack patterns"""
        sessions = data['sessions']
        commands = data['commands']
        
        # Time-based analysis
        hourly_distribution = Counter()
        for session in sessions:
            session_time = session['start_time']
            if isinstance(session_time, str):
                session_time = datetime.fromisoformat(session_time.replace('Z', '+00:00'))
            hourly_distribution[session_time.hour] += 1
        
        # Command sequence analysis
        command_sequences = self._analyze_command_sequences(commands)
        
        # Geographic analysis
        countries = Counter()
        for session in sessions:
            if session.get('geo_country'):
                countries[session['geo_country']] += 1
        
        # Username analysis
        usernames = Counter()
        for session in sessions:
            if session.get('username'):
                usernames[session['username']] += 1
        
        # Password analysis
        passwords = Counter()
        for session in sessions:
            if session.get('password') and session['password'] not in ['[PUBLIC_KEY]', 'unknown']:
                passwords[session['password']] += 1
        
        # Session duration analysis
        durations = []
        for session in sessions:
            if session.get('duration_seconds'):
                durations.append(session['duration_seconds'])
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        # Command timing analysis
        command_timings = []
        for cmd in commands:
            if cmd.get('execution_time_ms'):
                command_timings.append(cmd['execution_time_ms'])
        
        return {
            'hourly_distribution': dict(hourly_distribution),
            'command_sequences': command_sequences,
            'top_countries': countries.most_common(10),
            'top_usernames': usernames.most_common(10),
            'top_passwords': passwords.most_common(10),
            'avg_session_duration': avg_duration,
            'suspicious_command_ratio': sum(1 for c in commands if c.get('suspicious')) / len(commands) if commands else 0
        }
    
    def _analyze_command_sequences(self, commands: List[Dict]) -> List[Dict]:
        """Analyze common command sequences"""
        if not commands:
            return []
        
        # Group commands by session
        session_commands = defaultdict(list)
        for cmd in commands:
            session_commands[cmd['session_id']].append(cmd['command'])
        
        # Find common 2-command sequences
        sequences = Counter()
        for session_id, cmds in session_commands.items():
            for i in range(len(cmds) - 1):
                seq = (cmds[i], cmds[i + 1])
                sequences[seq] += 1
        
        # Return top sequences
        return [
            {
                'first_cmd': seq[0],
                'second_cmd': seq[1],
                'count': count
            }
            for seq, count in sequences.most_common(10)
        ]
    
    def _generate_insights(self, data: Dict, analysis: Dict) -> List[Dict]:
        """Generate psychological insights about attackers"""
        insights = []
        
        # Insight 1: Attacker type distribution
        total_classified = data['human_count'] + data['bot_count']
        if total_classified > 0:
            human_ratio = data['human_count'] / total_classified
            if human_ratio > 0.7:
                insights.append({
                    'title': 'Human-Driven Attacks Dominant',
                    'description': f'{human_ratio*100:.1f}% of attacks show human-like keystroke patterns, suggesting manual targeting rather than automated scanning.',
                    'implication': 'Your system may be specifically targeted by threat actors.',
                    'recommendation': 'Review logs for targeted attack indicators.'
                })
            elif human_ratio < 0.3:
                insights.append({
                    'title': 'Automated Attacks Predominant',
                    'description': f'{(1-human_ratio)*100:.1f}% of attacks are automated, indicating broad scanning activity.',
                    'implication': 'Part of widespread internet scanning, not necessarily targeted.',
                    'recommendation': 'Ensure basic security hygiene is in place.'
                })
        
        # Insight 2: Geographic concentration
        top_countries = analysis['top_countries']
        if top_countries and top_countries[0][1] / data['total_sessions'] > 0.5:
            insights.append({
                'title': f'Geographic Concentration: {top_countries[0][0]}',
                'description': f'{top_countries[0][1]} attacks ({top_countries[0][1]/data["total_sessions"]*100:.1f}%) originated from {top_countries[0][0]}.',
                'implication': 'Possible coordinated campaign or botnet operating from this region.',
                'recommendation': 'Consider geo-blocking if not serving users in this region.'
            })
        
        # Insight 3: TTP sophistication
        ttps = data['ttps']
        sophisticated_ttps = [t for t in ttps if self.TTP_DESCRIPTIONS.get(t['tactic'], {}).get('sophistication') == 'high']
        if sophisticated_ttps:
            insights.append({
                'title': 'Advanced Persistent Threat Indicators',
                'description': f'Detected {len(sophisticated_ttps)} sophisticated TTPs including: {", ".join(t["tactic"] for t in sophisticated_ttps[:3])}.',
                'implication': 'Attackers are using advanced techniques for persistence and evasion.',
                'recommendation': 'Implement advanced detection and incident response procedures.'
            })
        
        # Insight 4: Credential patterns
        top_passwords = analysis['top_passwords']
        common_passwords = ['123456', 'password', 'admin', 'root', '123456789']
        weak_attempts = sum(1 for p, _ in top_passwords if p in common_passwords)
        if weak_attempts > 0:
            insights.append({
                'title': 'Weak Password Attacks',
                'description': f'{weak_attempts} attempts used common weak passwords.',
                'implication': 'Attackers using password spraying and dictionary attacks.',
                'recommendation': 'Enforce strong password policies and implement MFA.'
            })
        
        # Insight 5: Session duration patterns
        avg_duration = analysis['avg_session_duration']
        if avg_duration > 300:  # More than 5 minutes
            insights.append({
                'title': 'Extended Session Durations',
                'description': f'Average session duration of {avg_duration/60:.1f} minutes indicates thorough exploration.',
                'implication': 'Attackers are taking time to map and understand the environment.',
                'recommendation': 'Monitor for data staging and exfiltration attempts.'
            })
        
        # Insight 6: Command sequence patterns
        sequences = analysis['command_sequences']
        if sequences and sequences[0]['count'] > 3:
            insights.append({
                'title': 'Repetitive Attack Patterns',
                'description': f'Common sequence "{sequences[0]["first_cmd"]}" → "{sequences[0]["second_cmd"]}" seen {sequences[0]["count"]} times.',
                'implication': 'Attackers following documented procedures or using automation.',
                'recommendation': 'Create detection rules for these specific sequences.'
            })
        
        # Insight 7: Suspicious activity ratio
        suspicious_ratio = analysis['suspicious_command_ratio']
        if suspicious_ratio > 0.3:
            insights.append({
                'title': 'High Malicious Activity Rate',
                'description': f'{suspicious_ratio*100:.1f}% of commands were flagged as suspicious.',
                'implication': 'Attackers are actively attempting malicious actions.',
                'recommendation': 'Review and block identified attack sources.'
            })
        
        return insights
    
    def _generate_html_report(self, data: Dict, analysis: Dict, insights: List[Dict]) -> str:
        """Generate HTML formatted report"""
        
        template_str = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Daily Attacker Psychology Report - {{ date }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        .section {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .section h2 {
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }
        .insight {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .insight h3 {
            margin-top: 0;
            color: #333;
        }
        .insight-meta {
            display: flex;
            gap: 20px;
            margin-top: 10px;
            font-size: 0.9em;
        }
        .implication {
            color: #856404;
            background: #fff3cd;
            padding: 5px 10px;
            border-radius: 3px;
        }
        .recommendation {
            color: #155724;
            background: #d4edda;
            padding: 5px 10px;
            border-radius: 3px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #667eea;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .ttp-item {
            display: flex;
            justify-content: space-between;
            padding: 10px;
            background: #f8f9fa;
            margin-bottom: 5px;
            border-radius: 5px;
        }
        .ttp-name {
            font-weight: bold;
            color: #667eea;
        }
        .ttp-count {
            background: #667eea;
            color: white;
            padding: 2px 10px;
            border-radius: 15px;
            font-size: 0.9em;
        }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #6c757d; }
        .footer {
            text-align: center;
            color: #666;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Daily Attacker Psychology Report</h1>
        <p>Analysis Period: {{ date }} | Generated: {{ generated_at }}</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">{{ total_sessions }}</div>
            <div class="stat-label">Total Sessions</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ total_commands }}</div>
            <div class="stat-label">Commands Executed</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ human_count }}</div>
            <div class="stat-label">Human Attackers</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">{{ bot_count }}</div>
            <div class="stat-label">Bot Attacks</div>
        </div>
    </div>
    
    <div class="section">
        <h2>🧠 Psychological Insights</h2>
        {% for insight in insights %}
        <div class="insight">
            <h3>{{ insight.title }}</h3>
            <p>{{ insight.description }}</p>
            <div class="insight-meta">
                <span class="implication">⚠️ {{ insight.implication }}</span>
                <span class="recommendation">✓ {{ insight.recommendation }}</span>
            </div>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>🎯 Observed TTPs (Tactics, Techniques, Procedures)</h2>
        {% for ttp in ttps %}
        <div class="ttp-item">
            <div>
                <span class="ttp-name">{{ ttp.tactic }}</span>
                {% if ttp.technique %}
                <small style="color: #666;">({{ ttp.technique }})</small>
                {% endif %}
            </div>
            <span class="ttp-count">{{ ttp.session_count }} sessions</span>
        </div>
        {% endfor %}
    </div>
    
    <div class="section">
        <h2>🌍 Geographic Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Country</th>
                    <th>Attack Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
                {% for country, count in top_countries %}
                <tr>
                    <td>{{ country }}</td>
                    <td>{{ count }}</td>
                    <td>{{ "%.1f"|format(count / total_sessions * 100) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>👤 Top Targeted Usernames</h2>
        <table>
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Attempt Count</th>
                </tr>
            </thead>
            <tbody>
                {% for username, count in top_usernames %}
                <tr>
                    <td><code>{{ username }}</code></td>
                    <td>{{ count }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>🔑 Common Password Attempts</h2>
        <table>
            <thead>
                <tr>
                    <th>Password</th>
                    <th>Attempt Count</th>
                </tr>
            </thead>
            <tbody>
                {% for password, count in top_passwords %}
                <tr>
                    <td><code>{{ password }}</code></td>
                    <td>{{ count }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>📊 Command Sequence Analysis</h2>
        <p>Most common command sequences observed:</p>
        <table>
            <thead>
                <tr>
                    <th>First Command</th>
                    <th>Second Command</th>
                    <th>Frequency</th>
                </tr>
            </thead>
            <tbody>
                {% for seq in command_sequences %}
                <tr>
                    <td><code>{{ seq.first_cmd }}</code></td>
                    <td><code>{{ seq.second_cmd }}</code></td>
                    <td>{{ seq.count }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>⏰ Hourly Attack Distribution</h2>
        <table>
            <thead>
                <tr>
                    <th>Hour (UTC)</th>
                    <th>Attack Count</th>
                </tr>
            </thead>
            <tbody>
                {% for hour, count in hourly_distribution.items()|sort %}
                <tr>
                    <td>{{ "%02d:00"|format(hour) }}</td>
                    <td>{{ count }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>📋 Methodology</h2>
        <p>This report analyzes attacker behavior using the following techniques:</p>
        <ul>
            <li><strong>Keystroke Dynamics Analysis:</strong> Distinguishes human attackers from bots based on typing patterns</li>
            <li><strong>TTP Mapping:</strong> Categorizes attacks using MITRE ATT&CK framework concepts</li>
            <li><strong>Behavioral Clustering:</strong> Groups similar attack patterns to identify campaigns</li>
            <li><strong>Temporal Analysis:</strong> Identifies attack timing patterns</li>
            <li><strong>Sequence Mining:</strong> Discovers common command sequences</li>
        </ul>
        <p><strong>Classification Method:</strong></p>
        <ul>
            <li><strong>Human:</strong> Variable keystroke timing (>50ms std dev), natural typing bursts</li>
            <li><strong>Bot:</strong> Consistent timing (<50ms), predictable patterns, low variance</li>
        </ul>
    </div>
    
    <div class="footer">
        <p>SSH Honeypot Analysis System | Report generated automatically</p>
        <p>For questions or more information, consult the honeypot documentation.</p>
    </div>
</body>
</html>
        '''
        
        template = jinja2.Template(template_str)
        
        return template.render(
            date=data['date'],
            generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_sessions=data['total_sessions'],
            total_commands=data['total_commands'],
            human_count=data['human_count'],
            bot_count=data['bot_count'],
            insights=insights,
            ttps=data['ttps'],
            top_countries=analysis['top_countries'],
            top_usernames=analysis['top_usernames'],
            top_passwords=analysis['top_passwords'],
            command_sequences=analysis['command_sequences'],
            hourly_distribution=analysis['hourly_distribution']
        )
    
    def _generate_text_report(self, data: Dict, analysis: Dict, insights: List[Dict]) -> str:
        """Generate plain text report"""
        lines = [
            "=" * 80,
            "DAILY ATTACKER PSYCHOLOGY REPORT",
            f"Analysis Period: {data['date']}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 80,
            "",
            "STATISTICS",
            "-" * 40,
            f"Total Sessions: {data['total_sessions']}",
            f"Total Commands: {data['total_commands']}",
            f"Human Attackers: {data['human_count']}",
            f"Bot Attacks: {data['bot_count']}",
            "",
            "PSYCHOLOGICAL INSIGHTS",
            "-" * 40,
        ]
        
        for i, insight in enumerate(insights, 1):
            lines.extend([
                f"\n{i}. {insight['title']}",
                f"   {insight['description']}",
                f"   Implication: {insight['implication']}",
                f"   Recommendation: {insight['recommendation']}",
            ])
        
        lines.extend([
            "",
            "TOP TTPs",
            "-" * 40,
        ])
        
        for ttp in data['ttps'][:10]:
            lines.append(f"  {ttp['tactic']}: {ttp['session_count']} sessions")
        
        lines.extend([
            "",
            "TOP COUNTRIES",
            "-" * 40,
        ])
        
        for country, count in analysis['top_countries'][:10]:
            lines.append(f"  {country}: {count}")
        
        lines.extend([
            "",
            "=" * 80,
        ])
        
        return '\n'.join(lines)
    
    def save_report(self, output_dir: str = '/app/reports', format: str = 'html'):
        """Generate and save report to file"""
        os.makedirs(output_dir, exist_ok=True)
        
        report_content = self.generate_report(format)
        
        filename = f"attacker_psychology_report_{self.report_date.strftime('%Y%m%d')}.{format}"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(report_content)
        
        logger.info(f"Report saved to {filepath}")
        return filepath


def generate_daily_report():
    """Generate daily report (can be called from cron)"""
    db = HoneypotDatabase()
    report = AttackerPsychologyReport(db)
    
    # Generate both HTML and text versions
    html_path = report.save_report(format='html')
    text_path = report.save_report(format='txt')
    
    # Update daily stats in database
    report.db.update_daily_stats(report.report_date)
    
    logger.info(f"Daily report generation complete: {html_path}, {text_path}")
    return html_path, text_path


if __name__ == '__main__':
    generate_daily_report()
