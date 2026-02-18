#!/usr/bin/env python3
"""
SSH Honeypot Server - Main Entry Point
A medium-interaction SSH honeypot with realistic Debian environment
"""

import paramiko
import socket
import threading
import logging
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import sqlite3
import hashlib
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/honeypot/ssh_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot.filesystem import FakeFilesystem
from honeypot.shell import FakeShell
from honeypot.database import HoneypotDatabase


class HoneypotSSHServer(paramiko.ServerInterface):
    """SSH Server Interface implementing authentication and session handling"""
    
    def __init__(self, client_ip: str, db: HoneypotDatabase):
        self.client_ip = client_ip
        self.db = db
        self.event = threading.Event()
        self.authenticated = False
        self.username = None
        self.password = None
        self.auth_attempts = 0
        self.session_start = None
        self.keystroke_timings: List[Dict] = []
        self.last_keystroke_time = None
        
    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Accept session channel requests"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username: str, password: str) -> int:
        """Log authentication attempts and accept all credentials"""
        self.auth_attempts += 1
        self.username = username
        self.password = password
        
        # Log authentication attempt
        self.db.log_auth_attempt(
            client_ip=self.client_ip,
            username=username,
            password=password,
            timestamp=datetime.now(),
            success=True  # Always accept for honeypot
        )
        
        logger.info(f"Auth attempt from {self.client_ip}: {username}:{password}")
        
        # Accept all credentials (honeypot behavior)
        self.authenticated = True
        return paramiko.AUTH_SUCCESSFUL
    
    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """Log public key authentication attempts"""
        key_fingerprint = hashlib.md5(key.get_fingerprint()).hexdigest()
        
        self.db.log_auth_attempt(
            client_ip=self.client_ip,
            username=username,
            password=f"[PUBLIC_KEY:{key_fingerprint}]",
            timestamp=datetime.now(),
            success=True
        )
        
        logger.info(f"Public key auth from {self.client_ip}: {username} (fp: {key_fingerprint})")
        
        self.authenticated = True
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username: str) -> str:
        """Return allowed authentication methods"""
        return 'password,publickey'
    
    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        """Accept shell requests"""
        self.event.set()
        self.session_start = datetime.now()
        return True
    
    def check_channel_pty_request(self, channel: paramiko.Channel, term: str, 
                                   width: int, height: int, pixelwidth: int, 
                                   pixelheight: int, modes: bytes) -> bool:
        """Accept PTY requests and store terminal info"""
        self.term = term
        self.term_width = width
        self.term_height = height
        return True
    
    def record_keystroke_timing(self, char: str, timestamp: float):
        """Record keystroke timing for bot detection analysis"""
        if self.last_keystroke_time is not None:
            interval = timestamp - self.last_keystroke_time
            self.keystroke_timings.append({
                'char': char,
                'interval_ms': interval * 1000,  # Convert to milliseconds
                'timestamp': datetime.fromtimestamp(timestamp)
            })
        self.last_keystroke_time = timestamp


class SSHHoneypot:
    """Main SSH Honeypot Server"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 2222, 
                 key_file: str = '/app/config/host_key_rsa'):
        self.host = host
        self.port = port
        self.key_file = key_file
        self.db = HoneypotDatabase()
        self.server_socket = None
        self.running = False
        self.active_sessions: Dict[str, threading.Thread] = {}
        
        # Generate or load host key
        self._setup_host_key()
        
    def _setup_host_key(self):
        """Generate or load RSA host key"""
        if not os.path.exists(self.key_file):
            logger.info("Generating new host key...")
            key = paramiko.RSAKey.generate(2048)
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            key.write_private_key_file(self.key_file)
            logger.info(f"Host key saved to {self.key_file}")
        else:
            logger.info(f"Loading existing host key from {self.key_file}")
            
    def _generate_server_banner(self) -> str:
        """Generate realistic Debian SSH banner"""
        banners = [
            "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1",
            "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u1",
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        ]
        return random.choice(banners)
    
    def handle_client(self, client_socket: socket.socket, client_ip: str, client_port: int):
        """Handle individual client connections"""
        logger.info(f"New connection from {client_ip}:{client_port}")
        
        transport = None
        try:
            # Create transport with custom banner
            transport = paramiko.Transport(client_socket)
            transport.local_version = self._generate_server_banner()
            
            # Add server key
            server_key = paramiko.RSAKey(filename=self.key_file)
            transport.add_server_key(server_key)
            
            # Set up honeypot server
            server = HoneypotSSHServer(client_ip, self.db)
            transport.start_server(server=server)
            
            # Wait for authentication
            channel = transport.accept(30)
            if channel is None:
                logger.warning(f"No channel established for {client_ip}")
                return
            
            # Wait for shell request
            server.event.wait(10)
            if not server.event.is_set():
                logger.warning(f"No shell request from {client_ip}")
                channel.close()
                return
            
            # Create session ID
            session_id = hashlib.sha256(
                f"{client_ip}:{time.time()}:{random.randint(0, 1000000)}".encode()
            ).hexdigest()[:16]
            
            # Log session start
            self.db.log_session_start(
                session_id=session_id,
                client_ip=client_ip,
                client_port=client_port,
                username=server.username or 'unknown',
                password=server.password or 'unknown',
                auth_method='password' if server.password else 'publickey',
                start_time=datetime.now()
            )
            
            # Start fake shell
            shell = FakeShell(
                channel=channel,
                client_ip=client_ip,
                session_id=session_id,
                db=self.db,
                username=server.username or 'root',
                server=server
            )
            
            logger.info(f"Starting shell session {session_id} for {client_ip}")
            shell.run()
            
            # Log session end
            self.db.log_session_end(
                session_id=session_id,
                end_time=datetime.now(),
                keystroke_timings=server.keystroke_timings
            )
            
            logger.info(f"Session {session_id} ended")
            
        except Exception as e:
            logger.error(f"Error handling client {client_ip}: {e}")
        finally:
            if transport:
                transport.close()
            try:
                client_socket.close()
            except:
                pass
    
    def start(self):
        """Start the SSH honeypot server"""
        self.running = True
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            
            logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, (client_ip, client_port) = self.server_socket.accept()
                    
                    # Handle client in new thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_ip, client_port),
                        daemon=True
                    )
                    client_thread.start()
                    
                    self.active_sessions[f"{client_ip}:{client_port}"] = client_thread
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
                        
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the SSH honeypot server"""
        logger.info("Stopping SSH Honeypot...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Wait for active sessions to complete
        for session_key, thread in list(self.active_sessions.items()):
            logger.info(f"Waiting for session {session_key} to complete...")
            thread.join(timeout=5)
        
        logger.info("SSH Honeypot stopped")


def main():
    """Main entry point"""
    import signal
    
    honeypot = SSHHoneypot(
        host=os.getenv('HONEYPOT_HOST', '0.0.0.0'),
        port=int(os.getenv('HONEYPOT_PORT', '2222')),
        key_file=os.getenv('HOST_KEY_FILE', '/app/config/host_key_rsa')
    )
    
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        honeypot.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    honeypot.start()


if __name__ == '__main__':
    main()
