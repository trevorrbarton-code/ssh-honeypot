#!/usr/bin/env python3
"""
Flask Dashboard - Real-time monitoring and analytics for SSH Honeypot
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List
from collections import Counter

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.database import HoneypotDatabase
from ml.keystroke_classifier import get_classifier

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'honeypot-secret-key')
socketio = SocketIO(app, cors_allowed_origins="*")

# Database instance
db = HoneypotDatabase()

# Global stats cache
stats_cache = {
    'last_update': None,
    'data': {}
}


def get_geoip_data(ip: str) -> Dict:
    """Get geolocation data for an IP (placeholder - integrate with GeoIP2)"""
    # This is a placeholder - in production, use GeoIP2 or similar service
    # For demo purposes, return simulated data
    
    # Use IP to generate consistent fake data
    ip_parts = ip.split('.')
    seed = sum(int(p) for p in ip_parts)
    
    countries = ['CN', 'RU', 'US', 'BR', 'IN', 'DE', 'NL', 'GB', 'FR', 'KR', 'VN', 'ID', 'TW', 'TR', 'RO']
    cities = ['Beijing', 'Moscow', 'New York', 'Sao Paulo', 'Mumbai', 'Berlin', 'Amsterdam', 
              'London', 'Paris', 'Seoul', 'Hanoi', 'Jakarta', 'Taipei', 'Istanbul', 'Bucharest']
    
    idx = seed % len(countries)
    
    return {
        'country': countries[idx],
        'city': cities[idx],
        'latitude': 20 + (seed % 60) + (seed % 100) / 100,
        'longitude': -120 + (seed % 240) + (seed % 100) / 100,
        'asn': f'AS{seed * 1000}',
        'isp': f'ISP-{countries[idx]}'
    }


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    try:
        hours = request.args.get('hours', 24, type=int)
        stats = db.get_attack_stats(hours=hours)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/sessions')
def get_sessions():
    """Get recent sessions"""
    try:
        limit = request.args.get('limit', 100, type=int)
        sessions = db.get_recent_sessions(limit=limit)
        
        # Convert datetime objects to strings for JSON serialization
        for session in sessions:
            for key in ['start_time', 'end_time', 'created_at']:
                if session.get(key):
                    session[key] = session[key].isoformat() if hasattr(session[key], 'isoformat') else str(session[key])
        
        return jsonify(sessions)
    except Exception as e:
        logger.error(f"Error getting sessions: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/session/<session_id>/commands')
def get_session_commands(session_id):
    """Get commands for a specific session"""
    try:
        commands = db.get_session_commands(session_id)
        
        # Convert datetime objects to strings
        for cmd in commands:
            if cmd.get('timestamp'):
                cmd['timestamp'] = cmd['timestamp'].isoformat() if hasattr(cmd['timestamp'], 'isoformat') else str(cmd['timestamp'])
        
        return jsonify(commands)
    except Exception as e:
        logger.error(f"Error getting session commands: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/geolocation')
def get_geolocation():
    """Get geolocation data for heatmap"""
    try:
        hours = request.args.get('hours', 24, type=int)
        geo_data = db.get_geolocation_data(hours=hours)
        
        # If no geo data in database, generate from sessions
        if not geo_data:
            sessions = db.get_recent_sessions(limit=500)
            seen_ips = set()
            
            for session in sessions:
                ip = session['client_ip']
                if ip not in seen_ips and not ip.startswith(('10.', '172.', '192.168.')):
                    seen_ips.add(ip)
                    geo = get_geoip_data(ip)
                    geo_data.append({
                        'ip': ip,
                        'country': geo['country'],
                        'city': geo['city'],
                        'lat': geo['latitude'],
                        'lon': geo['longitude'],
                        'count': 1
                    })
        
        return jsonify(geo_data)
    except Exception as e:
        logger.error(f"Error getting geolocation: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/commands/frequency')
def get_command_frequency():
    """Get command frequency analysis"""
    try:
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 50, type=int)
        
        # Get stats which include top commands
        stats = db.get_attack_stats(hours=hours)
        top_commands = stats.get('top_commands', [])
        
        # Format for visualization
        result = []
        for cmd, count in top_commands[:limit]:
            result.append({
                'command': cmd,
                'count': count,
                'category': categorize_command(cmd)
            })
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error getting command frequency: {e}")
        return jsonify({'error': str(e)}), 500


def categorize_command(command: str) -> str:
    """Categorize a command by type"""
    command = command.lower()
    
    categories = {
        'reconnaissance': ['uname', 'whoami', 'id', 'w', 'last', 'ps', 'netstat', 'ifconfig', 
                          'ip ', 'hostname', 'cat /etc/', 'cat /proc/', 'df', 'free', 'ls', 'pwd'],
        'file_operations': ['cat ', 'head ', 'tail ', 'grep ', 'find ', 'ls ', 'cd ', 'pwd'],
        'network': ['ping', 'traceroute', 'nslookup', 'dig', 'curl', 'wget', 'nc ', 'ncat ', 
                   'ssh ', 'scp ', 'netstat', 'ss ', 'nmap'],
        'privilege_escalation': ['sudo ', 'su ', 'passwd', 'chmod ', 'chown ', 'useradd', 'adduser'],
        'persistence': ['crontab', 'echo ', '>>', 'systemctl', 'service '],
        'data_exfiltration': ['scp ', 'rsync', 'curl.*-d', 'wget.*-O'],
        'reverse_shell': ['nc.*-e', 'ncat.*-e', 'bash -i', 'sh -i', 'python.*socket', 
                         'perl.*socket', 'ruby.*socket', 'mkfifo', 'backpipe'],
        'cryptomining': ['minerd', 'xmrig', 'stratum', 'mining'],
        'destructive': ['rm -rf', 'dd ', 'mkfs', 'fdisk', 'parted'],
        'download_execute': ['curl.*\|', 'wget.*\|', 'base64.*-d'],
    }
    
    for category, patterns in categories.items():
        for pattern in patterns:
            if pattern in command:
                return category
    
    return 'other'


@app.route('/api/classification/realtime')
def get_realtime_classification():
    """Get real-time human vs bot classification data"""
    try:
        sessions = db.get_recent_sessions(limit=100)
        
        human_count = sum(1 for s in sessions if s.get('classified_as') == 'human')
        bot_count = sum(1 for s in sessions if s.get('classified_as') == 'bot')
        unknown_count = len(sessions) - human_count - bot_count
        
        # Get confidence distribution
        confidence_ranges = {'high': 0, 'medium': 0, 'low': 0}
        for s in sessions:
            conf = s.get('classification_confidence', 0)
            if conf >= 0.8:
                confidence_ranges['high'] += 1
            elif conf >= 0.5:
                confidence_ranges['medium'] += 1
            else:
                confidence_ranges['low'] += 1
        
        # Recent classifications with details
        recent = []
        for s in sessions[:20]:
            if s.get('classified_as'):
                recent.append({
                    'session_id': s['session_id'],
                    'client_ip': s['client_ip'],
                    'classification': s['classified_as'],
                    'confidence': s.get('classification_confidence', 0),
                    'username': s.get('username'),
                    'commands_count': s.get('commands_count', 0),
                    'start_time': s['start_time'].isoformat() if hasattr(s['start_time'], 'isoformat') else str(s['start_time'])
                })
        
        return jsonify({
            'counts': {
                'human': human_count,
                'bot': bot_count,
                'unknown': unknown_count
            },
            'confidence_distribution': confidence_ranges,
            'recent_classifications': recent,
            'classification_rate': (human_count + bot_count) / len(sessions) * 100 if sessions else 0
        })
    except Exception as e:
        logger.error(f"Error getting classification data: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/classification/classify', methods=['POST'])
def classify_session():
    """Classify a specific session"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({'error': 'session_id required'}), 400
        
        # Get keystroke timings from database
        timings = db.get_keystroke_timings(session_id)
        
        if not timings:
            return jsonify({'error': 'No keystroke data found for session'}), 404
        
        # Classify
        classifier = get_classifier()
        result = classifier.classify(timings)
        
        # Update database with classification
        db.update_session_classification(
            session_id=session_id,
            classification=result['classification'],
            confidence=result['confidence']
        )
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error classifying session: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ttps')
def get_ttps():
    """Get TTPs (Tactics, Techniques, Procedures) summary"""
    try:
        days = request.args.get('days', 7, type=int)
        ttps = db.get_ttps_summary(days=days)
        return jsonify(ttps)
    except Exception as e:
        logger.error(f"Error getting TTPs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/daily-stats')
def get_daily_stats():
    """Get daily statistics"""
    try:
        days = request.args.get('days', 30, type=int)
        stats = db.get_daily_stats(days=days)
        
        # Parse JSON fields
        for stat in stats:
            for field in ['top_commands', 'top_countries', 'common_ttps']:
                if stat.get(field):
                    try:
                        stat[field] = json.loads(stat[field])
                    except:
                        stat[field] = []
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting daily stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/classifier/train', methods=['POST'])
def train_classifier():
    """Train/retrain the keystroke classifier"""
    try:
        classifier = get_classifier()
        results = classifier.train()
        return jsonify(results)
    except Exception as e:
        logger.error(f"Error training classifier: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/classifier/status')
def get_classifier_status():
    """Get classifier status and feature importance"""
    try:
        classifier = get_classifier()
        
        return jsonify({
            'is_trained': classifier.is_trained,
            'feature_importance': classifier.get_feature_importance()[:10] if classifier.is_trained else [],
            'model_type': type(classifier.model).__name__ if classifier.model else None
        })
    except Exception as e:
        logger.error(f"Error getting classifier status: {e}")
        return jsonify({'error': str(e)}), 500


# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info('Client connected to dashboard')
    emit('connected', {'data': 'Connected to honeypot dashboard'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected from dashboard')


def broadcast_updates():
    """Background thread to broadcast real-time updates"""
    while True:
        try:
            time.sleep(5)  # Update every 5 seconds
            
            # Get latest stats
            stats = db.get_attack_stats(hours=1)
            
            # Get recent sessions
            sessions = db.get_recent_sessions(limit=10)
            for s in sessions:
                for key in ['start_time', 'end_time', 'created_at']:
                    if s.get(key):
                        s[key] = s[key].isoformat() if hasattr(s[key], 'isoformat') else str(s[key])
            
            # Broadcast to all clients
            socketio.emit('stats_update', {
                'timestamp': datetime.now().isoformat(),
                'stats': stats,
                'recent_sessions': sessions
            })
            
        except Exception as e:
            logger.error(f"Error in broadcast thread: {e}")


# Start background thread
broadcast_thread = threading.Thread(target=broadcast_updates, daemon=True)
broadcast_thread.start()


if __name__ == '__main__':
    # Initialize classifier if needed
    classifier = get_classifier()
    if not classifier.is_trained:
        logger.info("Training classifier on startup...")
        classifier.train()
    
    # Run Flask app
    socketio.run(
        app,
        host=os.getenv('DASHBOARD_HOST', '0.0.0.0'),
        port=int(os.getenv('DASHBOARD_PORT', '8080')),
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    )
