#!/usr/bin/env python3
"""
SSH Honeypot Package
A medium-interaction SSH honeypot with realistic Debian environment
"""

__version__ = '1.0.0'
__author__ = 'Security Research Team'

from .ssh_server import SSHHoneypot
from .filesystem import FakeFilesystem, FakeFile
from .shell import FakeShell
from .database import HoneypotDatabase

__all__ = [
    'SSHHoneypot',
    'FakeFilesystem',
    'FakeFile', 
    'FakeShell',
    'HoneypotDatabase'
]
