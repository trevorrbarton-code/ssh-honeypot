#!/usr/bin/env python3
"""
Database Module - Handles all SQLite logging for the honeypot
"""

import sqlite3
import json
import os
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)


class HoneypotDatabase:
    """SQLite database handler for honeypot logging"""
    
    def __init__(self, db_path: str = '/app/data/honeypot.db'):
        self.db_path = db_path
        self.local = threading.local()
        self._init_database()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self.local, 'connection') or self.local.connection is None:
            self.local.connection = sqlite3.connect(self.db_path)
            self.local.connection.row_factory = sqlite3.Row
        return self.local.connection
    
    def _init_database(self):
        """Initialize database tables"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                client_ip TEXT NOT NULL,
                client_port INTEGER,
                username TEXT,
                password TEXT,
                auth_method TEXT,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                duration_seconds REAL,
                commands_count INTEGER DEFAULT 0,
                keystroke_data TEXT,  -- JSON array of keystroke timings
                classified_as TEXT,   -- 'human' or 'bot'
                classification_confidence REAL,
                geo_country TEXT,
                geo_city TEXT,
                geo_latitude REAL,
                geo_longitude REAL,
                asn TEXT,
                isp TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Authentication attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                client_ip TEXT NOT NULL,
                username TEXT,
                password TEXT,
                timestamp TIMESTAMP NOT NULL,
                success BOOLEAN,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        # Commands table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                command TEXT NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                execution_time_ms REAL,
                suspicious BOOLEAN DEFAULT FALSE,
                patterns_detected TEXT,  -- JSON array
                intent_classification TEXT,
                severity TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        # Keystroke timings table (for detailed ML analysis)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS keystroke_timings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                char TEXT,
                interval_ms REAL,
                timestamp TIMESTAMP NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        # TTPs (Tactics, Techniques, Procedures) table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ttps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                tactic TEXT NOT NULL,
                technique TEXT,
                procedure TEXT,
                first_seen TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                occurrence_count INTEGER DEFAULT 1,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            )
        ''')
        
        # Daily statistics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS daily_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE UNIQUE NOT NULL,
                total_sessions INTEGER DEFAULT 0,
                unique_ips INTEGER DEFAULT 0,
                total_commands INTEGER DEFAULT 0,
                suspicious_commands INTEGER DEFAULT 0,
                human_classified INTEGER DEFAULT 0,
                bot_classified INTEGER DEFAULT 0,
                top_commands TEXT,  -- JSON
                top_countries TEXT,  -- JSON
                common_ttps TEXT,  -- JSON
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(client_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_time ON commands(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_keystrokes_session ON keystroke_timings(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_attempts(client_ip)')
        
        conn.commit()
        logger.info("Database initialized successfully")
    
    def log_session_start(self, session_id: str, client_ip: str, client_port: int,
                          username: str, password: str, auth_method: str,
                          start_time: datetime, geo_data: Optional[Dict] = None):
        """Log the start of a new session"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Extract geo data if available
            country = city = asn = isp = None
            lat = lon = None
            
            if geo_data:
                country = geo_data.get('country')
                city = geo_data.get('city')
                lat = geo_data.get('latitude')
                lon = geo_data.get('longitude')
                asn = geo_data.get('asn')
                isp = geo_data.get('isp')
            
            cursor.execute('''
                INSERT INTO sessions 
                (session_id, client_ip, client_port, username, password, auth_method,
                 start_time, geo_country, geo_city, geo_latitude, geo_longitude, asn, isp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, client_ip, client_port, username, password, auth_method,
                  start_time, country, city, lat, lon, asn, isp))
            
            conn.commit()
            logger.info(f"Session {session_id} started from {client_ip}")
            
        except Exception as e:
            logger.error(f"Error logging session start: {e}")
    
    def log_session_end(self, session_id: str, end_time: datetime,
                        keystroke_timings: List[Dict]):
        """Log the end of a session with keystroke data"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Get start time and calculate duration
            cursor.execute('SELECT start_time FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            
            if row:
                start_time = datetime.fromisoformat(row['start_time'])
                duration = (end_time - start_time).total_seconds()
                
                # Get command count
                cursor.execute('SELECT COUNT(*) as count FROM commands WHERE session_id = ?', (session_id,))
                cmd_count = cursor.fetchone()['count']
                
                # Store keystroke data as JSON
                keystroke_json = json.dumps(keystroke_timings)
                
                cursor.execute('''
                    UPDATE sessions 
                    SET end_time = ?, duration_seconds = ?, commands_count = ?, keystroke_data = ?
                    WHERE session_id = ?
                ''', (end_time, duration, cmd_count, keystroke_json, session_id))
                
                # Store individual keystroke timings
                for kt in keystroke_timings:
                    cursor.execute('''
                        INSERT INTO keystroke_timings (session_id, char, interval_ms, timestamp)
                        VALUES (?, ?, ?, ?)
                    ''', (session_id, kt.get('char'), kt.get('interval_ms'), kt.get('timestamp')))
                
                conn.commit()
                logger.info(f"Session {session_id} ended, duration: {duration:.2f}s")
                
        except Exception as e:
            logger.error(f"Error logging session end: {e}")
    
    def update_session_classification(self, session_id: str, classification: str,
                                       confidence: float):
        """Update session with human/bot classification"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE sessions 
                SET classified_as = ?, classification_confidence = ?
                WHERE session_id = ?
            ''', (classification, confidence, session_id))
            
            conn.commit()
            logger.info(f"Session {session_id} classified as {classification} ({confidence:.2%})")
            
        except Exception as e:
            logger.error(f"Error updating session classification: {e}")
    
    def log_auth_attempt(self, client_ip: str, username: str, password: str,
                         timestamp: datetime, success: bool,
                         session_id: Optional[str] = None):
        """Log an authentication attempt"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO auth_attempts (session_id, client_ip, username, password, timestamp, success)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session_id, client_ip, username, password, timestamp, success))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error logging auth attempt: {e}")
    
    def log_command(self, session_id: str, command: str, timestamp: datetime,
                    analysis: Dict, execution_time_ms: Optional[float] = None):
        """Log a command execution with analysis"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            patterns = json.dumps(analysis.get('patterns', []))
            
            cursor.execute('''
                INSERT INTO commands 
                (session_id, command, timestamp, execution_time_ms, suspicious, 
                 patterns_detected, intent_classification, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, command, timestamp, execution_time_ms,
                  analysis.get('suspicious', False), patterns,
                  analysis.get('intent', 'unknown'), analysis.get('severity', 'low')))
            
            # Also log TTP if suspicious
            if analysis.get('suspicious') and analysis.get('intent') != 'unknown':
                self._log_ttp(session_id, analysis.get('intent'), 
                              analysis.get('patterns', [None])[0], command, timestamp)
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error logging command: {e}")
    
    def _log_ttp(self, session_id: str, tactic: str, technique: Optional[str],
                 procedure: str, timestamp: datetime):
        """Log a TTP (Tactic, Technique, Procedure)"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Check if this TTP already exists for this session
            cursor.execute('''
                SELECT id, occurrence_count FROM ttps 
                WHERE session_id = ? AND tactic = ? AND technique = ?
            ''', (session_id, tactic, technique))
            
            row = cursor.fetchone()
            
            if row:
                # Update existing TTP
                cursor.execute('''
                    UPDATE ttps 
                    SET last_seen = ?, occurrence_count = ?, procedure = ?
                    WHERE id = ?
                ''', (timestamp, row['occurrence_count'] + 1, procedure, row['id']))
            else:
                # Insert new TTP
                cursor.execute('''
                    INSERT INTO ttps (session_id, tactic, technique, procedure, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (session_id, tactic, technique, procedure, timestamp, timestamp))
            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error logging TTP: {e}")
    
    def get_recent_sessions(self, limit: int = 100) -> List[Dict]:
        """Get recent sessions"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM sessions 
                ORDER BY start_time DESC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting recent sessions: {e}")
            return []
    
    def get_session_commands(self, session_id: str) -> List[Dict]:
        """Get all commands for a session"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM commands 
                WHERE session_id = ?
                ORDER BY timestamp ASC
            ''', (session_id,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting session commands: {e}")
            return []
    
    def get_keystroke_timings(self, session_id: str) -> List[Dict]:
        """Get keystroke timings for a session"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT interval_ms FROM keystroke_timings 
                WHERE session_id = ? AND interval_ms IS NOT NULL
                ORDER BY timestamp ASC
            ''', (session_id,))
            
            rows = cursor.fetchall()
            return [{'interval_ms': row['interval_ms']} for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting keystroke timings: {e}")
            return []
    
    def get_attack_stats(self, hours: int = 24) -> Dict:
        """Get attack statistics for the last N hours"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            since = datetime.now() - __import__('datetime').timedelta(hours=hours)
            
            # Total sessions
            cursor.execute('''
                SELECT COUNT(*) as count FROM sessions 
                WHERE start_time > ?
            ''', (since,))
            total_sessions = cursor.fetchone()['count']
            
            # Unique IPs
            cursor.execute('''
                SELECT COUNT(DISTINCT client_ip) as count FROM sessions 
                WHERE start_time > ?
            ''', (since,))
            unique_ips = cursor.fetchone()['count']
            
            # Total commands
            cursor.execute('''
                SELECT COUNT(*) as count FROM commands 
                WHERE timestamp > ?
            ''', (since,))
            total_commands = cursor.fetchone()['count']
            
            # Suspicious commands
            cursor.execute('''
                SELECT COUNT(*) as count FROM commands 
                WHERE timestamp > ? AND suspicious = TRUE
            ''', (since,))
            suspicious_commands = cursor.fetchone()['count']
            
            # Human vs Bot classification
            cursor.execute('''
                SELECT classified_as, COUNT(*) as count FROM sessions 
                WHERE start_time > ? AND classified_as IS NOT NULL
                GROUP BY classified_as
            ''', (since,))
            classifications = {row['classified_as']: row['count'] for row in cursor.fetchall()}
            
            # Top countries
            cursor.execute('''
                SELECT geo_country, COUNT(*) as count FROM sessions 
                WHERE start_time > ? AND geo_country IS NOT NULL
                GROUP BY geo_country
                ORDER BY count DESC
                LIMIT 10
            ''', (since,))
            top_countries = [(row['geo_country'], row['count']) for row in cursor.fetchall()]
            
            # Top commands
            cursor.execute('''
                SELECT command, COUNT(*) as count FROM commands 
                WHERE timestamp > ?
                GROUP BY command
                ORDER BY count DESC
                LIMIT 20
            ''', (since,))
            top_commands = [(row['command'], row['count']) for row in cursor.fetchall()]
            
            return {
                'total_sessions': total_sessions,
                'unique_ips': unique_ips,
                'total_commands': total_commands,
                'suspicious_commands': suspicious_commands,
                'human_count': classifications.get('human', 0),
                'bot_count': classifications.get('bot', 0),
                'top_countries': top_countries,
                'top_commands': top_commands,
                'time_range_hours': hours
            }
            
        except Exception as e:
            logger.error(f"Error getting attack stats: {e}")
            return {}
    
    def get_geolocation_data(self, hours: int = 24) -> List[Dict]:
        """Get geolocation data for attack heatmap"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            since = datetime.now() - __import__('datetime').timedelta(hours=hours)
            
            cursor.execute('''
                SELECT client_ip, geo_country, geo_city, geo_latitude, geo_longitude,
                       COUNT(*) as attack_count
                FROM sessions 
                WHERE start_time > ? AND geo_latitude IS NOT NULL
                GROUP BY client_ip
            ''', (since,))
            
            rows = cursor.fetchall()
            return [{
                'ip': row['client_ip'],
                'country': row['geo_country'],
                'city': row['geo_city'],
                'lat': row['geo_latitude'],
                'lon': row['geo_longitude'],
                'count': row['attack_count']
            } for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting geolocation data: {e}")
            return []
    
    def get_ttps_summary(self, days: int = 7) -> List[Dict]:
        """Get TTPs summary for reporting"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            since = datetime.now() - __import__('datetime').timedelta(days=days)
            
            cursor.execute('''
                SELECT tactic, technique, COUNT(*) as count,
                       SUM(occurrence_count) as total_occurrences
                FROM ttps 
                WHERE first_seen > ?
                GROUP BY tactic, technique
                ORDER BY count DESC
            ''', (since,))
            
            rows = cursor.fetchall()
            return [{
                'tactic': row['tactic'],
                'technique': row['technique'],
                'session_count': row['count'],
                'total_occurrences': row['total_occurrences']
            } for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting TTPs summary: {e}")
            return []
    
    def get_daily_stats(self, days: int = 30) -> List[Dict]:
        """Get daily statistics"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM daily_stats 
                WHERE date > date('now', '-{} days')
                ORDER BY date DESC
            '''.format(days))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
            
        except Exception as e:
            logger.error(f"Error getting daily stats: {e}")
            return []
    
    def update_daily_stats(self, date: datetime):
        """Update daily statistics for a specific date"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            date_str = date.strftime('%Y-%m-%d')
            start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_of_day = start_of_day + __import__('datetime').timedelta(days=1)
            
            # Calculate stats
            cursor.execute('''
                SELECT COUNT(*) as sessions FROM sessions 
                WHERE start_time >= ? AND start_time < ?
            ''', (start_of_day, end_of_day))
            total_sessions = cursor.fetchone()['sessions']
            
            cursor.execute('''
                SELECT COUNT(DISTINCT client_ip) as ips FROM sessions 
                WHERE start_time >= ? AND start_time < ?
            ''', (start_of_day, end_of_day))
            unique_ips = cursor.fetchone()['ips']
            
            cursor.execute('''
                SELECT COUNT(*) as commands FROM commands 
                WHERE timestamp >= ? AND timestamp < ?
            ''', (start_of_day, end_of_day))
            total_commands = cursor.fetchone()['commands']
            
            cursor.execute('''
                SELECT COUNT(*) as suspicious FROM commands 
                WHERE timestamp >= ? AND timestamp < ? AND suspicious = TRUE
            ''', (start_of_day, end_of_day))
            suspicious_commands = cursor.fetchone()['suspicious']
            
            cursor.execute('''
                SELECT classified_as, COUNT(*) as count FROM sessions 
                WHERE start_time >= ? AND start_time < ? AND classified_as IS NOT NULL
                GROUP BY classified_as
            ''', (start_of_day, end_of_day))
            
            human_count = 0
            bot_count = 0
            for row in cursor.fetchall():
                if row['classified_as'] == 'human':
                    human_count = row['count']
                elif row['classified_as'] == 'bot':
                    bot_count = row['count']
            
            # Top commands
            cursor.execute('''
                SELECT command, COUNT(*) as count FROM commands 
                WHERE timestamp >= ? AND timestamp < ?
                GROUP BY command
                ORDER BY count DESC
                LIMIT 10
            ''', (start_of_day, end_of_day))
            top_commands = json.dumps([{'command': row['command'], 'count': row['count']} 
                                       for row in cursor.fetchall()])
            
            # Top countries
            cursor.execute('''
                SELECT geo_country, COUNT(*) as count FROM sessions 
                WHERE start_time >= ? AND start_time < ? AND geo_country IS NOT NULL
                GROUP BY geo_country
                ORDER BY count DESC
                LIMIT 10
            ''', (start_of_day, end_of_day))
            top_countries = json.dumps([{'country': row['geo_country'], 'count': row['count']} 
                                        for row in cursor.fetchall()])
            
            # Common TTPs
            cursor.execute('''
                SELECT tactic, COUNT(*) as count FROM ttps 
                WHERE first_seen >= ? AND first_seen < ?
                GROUP BY tactic
                ORDER BY count DESC
                LIMIT 10
            ''', (start_of_day, end_of_day))
            common_ttps = json.dumps([{'tactic': row['tactic'], 'count': row['count']} 
                                      for row in cursor.fetchall()])
            
            # Insert or update daily stats
            cursor.execute('''
                INSERT INTO daily_stats 
                (date, total_sessions, unique_ips, total_commands, suspicious_commands,
                 human_classified, bot_classified, top_commands, top_countries, common_ttps)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(date) DO UPDATE SET
                    total_sessions = excluded.total_sessions,
                    unique_ips = excluded.unique_ips,
                    total_commands = excluded.total_commands,
                    suspicious_commands = excluded.suspicious_commands,
                    human_classified = excluded.human_classified,
                    bot_classified = excluded.bot_classified,
                    top_commands = excluded.top_commands,
                    top_countries = excluded.top_countries,
                    common_ttps = excluded.common_ttps,
                    updated_at = CURRENT_TIMESTAMP
            ''', (date_str, total_sessions, unique_ips, total_commands, suspicious_commands,
                  human_count, bot_count, top_commands, top_countries, common_ttps))
            
            conn.commit()
            logger.info(f"Daily stats updated for {date_str}")
            
        except Exception as e:
            logger.error(f"Error updating daily stats: {e}")
    
    def close(self):
        """Close database connection"""
        if hasattr(self.local, 'connection') and self.local.connection:
            self.local.connection.close()
            self.local.connection = None
