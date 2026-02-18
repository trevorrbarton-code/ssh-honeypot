#!/usr/bin/env python3
"""
Fake Shell - Simulates a realistic bash shell environment
"""

import re
import random
import time
from datetime import datetime
from typing import List, Tuple, Optional
import paramiko


class FakeShell:
    """Interactive fake shell for honeypot sessions"""
    
    # Common commands that attackers run
    COMMON_COMMANDS = [
        'uname -a', 'cat /etc/passwd', 'cat /etc/shadow', 'id', 'whoami',
        'w', 'last', 'ps aux', 'netstat -an', 'ifconfig', 'ip addr',
        'cat /proc/cpuinfo', 'cat /proc/meminfo', 'df -h', 'free -m',
        'ls -la', 'pwd', 'cd /tmp', 'cd /root', 'cd /var/www',
        'wget', 'curl', 'apt-get update', 'apt-get install',
        'yum update', 'yum install', 'dpkg -l', 'rpm -qa',
        'find / -name *.conf', 'find / -perm -4000', 'find / -writable',
        'crontab -l', 'cat /etc/crontab', 'systemctl list-units',
        'service --status-all', 'cat /etc/hosts', 'hostname',
        'cat /etc/resolv.conf', 'nslookup', 'ping', 'traceroute',
        'ssh', 'scp', 'sftp', 'nc', 'ncat', 'nmap',
        'python', 'python3', 'perl', 'ruby', 'php',
        'bash -i', '/bin/sh', '/bin/bash', 'exec',
        'mkfifo', 'mknod', 'mknod backpipe p',
        'history', 'cat ~/.bash_history',
        'echo', 'printf', 'cat', 'tac', 'head', 'tail',
        'grep', 'awk', 'sed', 'cut', 'sort', 'uniq',
        'base64', 'xxd', 'od', 'hexdump',
        'chmod', 'chown', 'chgrp', 'umask',
        'useradd', 'userdel', 'passwd', 'su', 'sudo',
        'mount', 'umount', 'fdisk', 'parted',
        'tar', 'gzip', 'gunzip', 'zip', 'unzip',
        'git clone', 'git pull', 'git status',
        'docker ps', 'docker images', 'kubectl',
        'mysql', 'psql', 'mongo', 'redis-cli',
        'cat /var/log/auth.log', 'cat /var/log/syslog',
        'dmesg', 'journalctl', 'tail -f',
        'rm -rf', 'dd', 'mkfs', 'fdisk',
        'openssl', 'ssh-keygen', 'gpg',
        'minerd', 'xmrig', 'stratum',
        'iptables', 'ufw', 'firewall-cmd',
    ]
    
    # Suspicious patterns indicating malicious intent
    SUSPICIOUS_PATTERNS = [
        (r'rm\s+-rf\s+/', 'destructive_command'),
        (r'mkfifo.*backpipe', 'reverse_shell_setup'),
        (r'bash\s+-i', 'interactive_shell_attempt'),
        (r'nc\s+\d+\.\d+\.\d+\.\d+', 'netcat_connection'),
        (r'ncat\s+\d+\.\d+\.\d+\.\d+', 'ncat_connection'),
        (r'python.*socket', 'python_reverse_shell'),
        (r'python3.*socket', 'python_reverse_shell'),
        (r'perl.*socket', 'perl_reverse_shell'),
        (r'ruby.*socket', 'ruby_reverse_shell'),
        (r'php.*fsockopen', 'php_reverse_shell'),
        (r'wget.*http', 'download_attempt'),
        (r'curl.*http', 'download_attempt'),
        (r'curl.*\|.*bash', 'pipe_to_shell'),
        (r'wget.*\|.*bash', 'pipe_to_shell'),
        (r'base64\s+-d', 'base64_decoding'),
        (r'eval\s*\(', 'eval_usage'),
        (r'exec\s*\(', 'exec_usage'),
        (r'system\s*\(', 'system_call'),
        (r'chmod\s+\+x', 'making_executable'),
        (r'chmod\s+777', 'permissive_permissions'),
        (r'useradd', 'user_creation'),
        (r'adduser', 'user_creation'),
        (r'passwd', 'password_change'),
        (r'crontab.*-e', 'cron_modification'),
        (r'echo.*>>.*cron', 'cron_backdoor'),
        (r'ssh.*-R', 'reverse_ssh_tunnel'),
        (r'ssh.*-D', 'dynamic_port_forward'),
        (r'minerd', 'cryptomining'),
        (r'xmrig', 'cryptomining'),
        (r'stratum', 'mining_pool'),
        (r'dd.*if=/dev/zero', 'disk_wipe_attempt'),
        (r'mkfs', 'filesystem_creation'),
        (r'iptables.*-F', 'firewall_flush'),
        (r'.*>', 'output_redirection'),
        (r'.*>>', 'append_redirection'),
        (r'.*\|', 'pipe_usage'),
    ]
    
    def __init__(self, channel: paramiko.Channel, client_ip: str, 
                 session_id: str, db, username: str = 'root',
                 server=None):
        self.channel = channel
        self.client_ip = client_ip
        self.session_id = session_id
        self.db = db
        self.username = username
        self.server = server
        self.fs = None  # Will be set by ssh_server
        self.running = True
        self.command_history: List[str] = []
        self.session_start = datetime.now()
        
        # Import here to avoid circular dependency
        from honeypot.filesystem import FakeFilesystem
        self.fs = FakeFilesystem()
        
        # Set initial directory based on user
        if username == 'root':
            self.fs.current_path = '/root'
        else:
            self.fs.current_path = f'/home/{username}'
            # Create home directory if it doesn't exist
            if not self.fs.file_exists(self.fs.current_path):
                self.fs.current_path = '/tmp'
    
    def send(self, data: str):
        """Send data to the client"""
        try:
            self.channel.send(data.encode('utf-8'))
        except:
            self.running = False
    
    def recv(self, size: int = 1024) -> str:
        """Receive data from client with keystroke timing"""
        try:
            data = self.channel.recv(size)
            if not data:
                return ''
            
            # Record keystroke timing if server is available
            if self.server and len(data) == 1:
                current_time = time.time()
                char = data.decode('utf-8', errors='ignore')
                if char:
                    self.server.record_keystroke_timing(char, current_time)
            
            return data.decode('utf-8', errors='ignore')
        except:
            self.running = False
            return ''
    
    def get_prompt(self) -> str:
        """Generate bash prompt"""
        hostname = 'debian-server'
        cwd = self.fs.get_current_path()
        
        # Shorten home directory
        if cwd.startswith('/root'):
            cwd = cwd.replace('/root', '~')
        elif cwd.startswith(f'/home/{self.username}'):
            cwd = cwd.replace(f'/home/{self.username}', '~')
        
        # Root gets #, others get $
        symbol = '#' if self.username == 'root' else '$'
        
        return f"{self.username}@{hostname}:{cwd}{symbol} "
    
    def send_welcome(self):
        """Send welcome message and MOTD"""
        # Clear screen and position cursor
        self.send('\r\n')
        
        # Send MOTD
        motd = '''Linux debian-server 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

Last login: {} from {}
'''.format(
            (datetime.now() - random_duration()).strftime('%a %b %d %H:%M:%S'),
            self.client_ip
        )
        
        self.send(motd + '\r\n')
    
    def parse_command(self, command_line: str) -> Tuple[str, List[str]]:
        """Parse command line into command and arguments"""
        parts = command_line.strip().split()
        if not parts:
            return '', []
        
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        return command, args
    
    def analyze_command(self, command_line: str) -> dict:
        """Analyze command for suspicious patterns"""
        analysis = {
            'command': command_line,
            'suspicious': False,
            'patterns': [],
            'intent': 'unknown',
            'severity': 'low'
        }
        
        # Check for suspicious patterns
        for pattern, classification in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, command_line, re.IGNORECASE):
                analysis['suspicious'] = True
                analysis['patterns'].append(classification)
        
        # Determine intent and severity
        if analysis['patterns']:
            destructive_patterns = [
                'destructive_command', 'disk_wipe_attempt', 'firewall_flush'
            ]
            reverse_shell_patterns = [
                'reverse_shell_setup', 'interactive_shell_attempt',
                'netcat_connection', 'ncat_connection', 'python_reverse_shell',
                'perl_reverse_shell', 'ruby_reverse_shell', 'php_reverse_shell'
            ]
            persistence_patterns = [
                'user_creation', 'cron_modification', 'cron_backdoor'
            ]
            
            if any(p in analysis['patterns'] for p in destructive_patterns):
                analysis['intent'] = 'destructive'
                analysis['severity'] = 'critical'
            elif any(p in analysis['patterns'] for p in reverse_shell_patterns):
                analysis['intent'] = 'reverse_shell'
                analysis['severity'] = 'high'
            elif any(p in analysis['patterns'] for p in persistence_patterns):
                analysis['intent'] = 'persistence'
                analysis['severity'] = 'high'
            elif 'cryptomining' in analysis['patterns']:
                analysis['intent'] = 'cryptomining'
                analysis['severity'] = 'medium'
            elif 'download_attempt' in analysis['patterns']:
                analysis['intent'] = 'download'
                analysis['severity'] = 'medium'
            else:
                analysis['intent'] = 'reconnaissance'
                analysis['severity'] = 'low'
        
        return analysis
    
    def execute_command(self, command_line: str) -> str:
        """Execute a command and return output"""
        if not command_line.strip():
            return ''
        
        command, args = self.parse_command(command_line)
        
        # Log command execution
        execution_time = datetime.now()
        
        # Analyze command
        analysis = self.analyze_command(command_line)
        
        # Log to database
        self.db.log_command(
            session_id=self.session_id,
            command=command_line,
            timestamp=execution_time,
            analysis=analysis
        )
        
        # Execute command
        output = self._handle_command(command, args, command_line)
        
        # Add to history
        self.command_history.append(command_line)
        
        return output
    
    def _handle_command(self, command: str, args: List[str], full_line: str) -> str:
        """Handle specific commands"""
        
        # Built-in commands
        handlers = {
            'ls': self._cmd_ls,
            'll': self._cmd_ll,
            'dir': self._cmd_ls,
            'cd': self._cmd_cd,
            'pwd': self._cmd_pwd,
            'cat': self._cmd_cat,
            'head': self._cmd_head,
            'tail': self._cmd_tail,
            'grep': self._cmd_grep,
            'find': self._cmd_find,
            'ps': self._cmd_ps,
            'whoami': self._cmd_whoami,
            'id': self._cmd_id,
            'uname': self._cmd_uname,
            'w': self._cmd_w,
            'last': self._cmd_last,
            'df': self._cmd_df,
            'free': self._cmd_free,
            'ifconfig': self._cmd_ifconfig,
            'ip': self._cmd_ip,
            'netstat': self._cmd_netstat,
            'ss': self._cmd_ss,
            'hostname': self._cmd_hostname,
            'echo': self._cmd_echo,
            'which': self._cmd_which,
            'history': self._cmd_history,
            'clear': self._cmd_clear,
            'exit': self._cmd_exit,
            'logout': self._cmd_exit,
            'wget': self._cmd_wget,
            'curl': self._cmd_curl,
            'apt-get': self._cmd_apt,
            'apt': self._cmd_apt,
            'yum': self._cmd_yum,
            'systemctl': self._cmd_systemctl,
            'service': self._cmd_service,
            'useradd': self._cmd_useradd,
            'adduser': self._cmd_useradd,
            'passwd': self._cmd_passwd,
            'chmod': self._cmd_chmod,
            'chown': self._cmd_chown,
            'rm': self._cmd_rm,
            'cp': self._cmd_cp,
            'mv': self._cmd_mv,
            'mkdir': self._cmd_mkdir,
            'rmdir': self._cmd_rmdir,
            'touch': self._cmd_touch,
            'ping': self._cmd_ping,
            'traceroute': self._cmd_traceroute,
            'nslookup': self._cmd_nslookup,
            'dig': self._cmd_dig,
            'python': self._cmd_python,
            'python3': self._cmd_python,
            'perl': self._cmd_perl,
            'ruby': self._cmd_ruby,
            'php': self._cmd_php,
            'nc': self._cmd_nc,
            'ncat': self._cmd_nc,
            'nmap': self._cmd_nmap,
            'ssh': self._cmd_ssh,
            'scp': self._cmd_scp,
            'docker': self._cmd_docker,
            'kubectl': self._cmd_kubectl,
            'mysql': self._cmd_mysql,
            'psql': self._cmd_psql,
            'mongo': self._cmd_mongo,
            'redis-cli': self._cmd_redis,
            'git': self._cmd_git,
            'tar': self._cmd_tar,
            'gzip': self._cmd_gzip,
            'gunzip': self._cmd_gzip,
            'zip': self._cmd_zip,
            'unzip': self._cmd_zip,
            'base64': self._cmd_base64,
            'xxd': self._cmd_xxd,
            'od': self._cmd_od,
            'hexdump': self._cmd_hexdump,
            'openssl': self._cmd_openssl,
            'ssh-keygen': self._cmd_ssh_keygen,
            'crontab': self._cmd_crontab,
            'iptables': self._cmd_iptables,
            'ufw': self._cmd_ufw,
            'dmesg': self._cmd_dmesg,
            'journalctl': self._cmd_journalctl,
            'uptime': self._cmd_uptime,
            'date': self._cmd_date,
            'who': self._cmd_who,
            'users': self._cmd_users,
            'groups': self._cmd_groups,
            'env': self._cmd_env,
            'export': self._cmd_export,
            'source': self._cmd_source,
            '.': self._cmd_source,
            'alias': self._cmd_alias,
            'unalias': self._cmd_unalias,
            'type': self._cmd_type,
            'help': self._cmd_help,
            'man': self._cmd_man,
            'info': self._cmd_info,
            'whatis': self._cmd_whatis,
            'apropos': self._cmd_apropos,
            'whereis': self._cmd_whereis,
            'locate': self._cmd_locate,
            'updatedb': self._cmd_updatedb,
            'su': self._cmd_su,
            'sudo': self._cmd_sudo,
            'mount': self._cmd_mount,
            'umount': self._cmd_umount,
            'fdisk': self._cmd_fdisk,
            'parted': self._cmd_parted,
            'mkfs': self._cmd_mkfs,
            'fsck': self._cmd_fsck,
            'dd': self._cmd_dd,
            'sync': self._cmd_sync,
            'reboot': self._cmd_reboot,
            'shutdown': self._cmd_shutdown,
            'poweroff': self._cmd_poweroff,
            'halt': self._cmd_halt,
            'init': self._cmd_init,
            'telinit': self._cmd_init,
            'runlevel': self._cmd_runlevel,
            'kill': self._cmd_kill,
            'killall': self._cmd_killall,
            'pkill': self._cmd_pkill,
            'pgrep': self._cmd_pgrep,
            'top': self._cmd_top,
            'htop': self._cmd_htop,
            'vmstat': self._cmd_vmstat,
            'iostat': self._cmd_iostat,
            'mpstat': self._cmd_mpstat,
            'sar': self._cmd_sar,
            'pidstat': self._cmd_pidstat,
            'tload': self._cmd_tload,
            'watch': self._cmd_watch,
            'screen': self._cmd_screen,
            'tmux': self._cmd_tmux,
            'nohup': self._cmd_nohup,
            'disown': self._cmd_disown,
            'jobs': self._cmd_jobs,
            'fg': self._cmd_fg,
            'bg': self._cmd_bg,
            'nice': self._cmd_nice,
            'renice': self._cmd_renice,
            'time': self._cmd_time,
            'timeout': self._cmd_timeout,
            'chroot': self._cmd_chroot,
            'ldd': self._cmd_ldd,
            'ldconfig': self._cmd_ldconfig,
            'locale': self._cmd_locale,
            'localedef': self._cmd_localedef,
            'tzselect': self._cmd_tzselect,
            'tzconfig': self._cmd_tzconfig,
            'hwclock': self._cmd_hwclock,
            'timedatectl': self._cmd_timedatectl,
            'hostnamectl': self._cmd_hostnamectl,
            'localectl': self._cmd_localectl,
            'loginctl': self._cmd_loginctl,
            'machinectl': self._cmd_machinectl,
            'busctl': self._cmd_busctl,
            'systemd-analyze': self._cmd_systemd_analyze,
            'systemd-cgtop': self._cmd_systemd_cgtop,
            'systemd-cgls': self._cmd_systemd_cgls,
            'systemd-resolve': self._cmd_systemd_resolve,
            'systemd-delta': self._cmd_systemd_delta,
            'systemd-detect-virt': self._cmd_systemd_detect_virt,
            'systemd-escape': self._cmd_systemd_escape,
            'systemd-path': self._cmd_systemd_path,
            'systemd-run': self._cmd_systemd_run,
            'systemd-inhibit': self._cmd_systemd_inhibit,
            'systemd-tmpfiles': self._cmd_systemd_tmpfiles,
            'systemd-sysusers': self._cmd_systemd_sysusers,
            'systemd-machine-id-setup': self._cmd_systemd_machine_id_setup,
        }
        
        handler = handlers.get(command)
        if handler:
            return handler(args)
        
        # Check if it's a path to an executable
        if command.startswith('./') or command.startswith('/'):
            return f"bash: {command}: No such file or directory\r\n"
        
        # Unknown command
        return f"bash: {command}: command not found\r\n"
    
    # Command implementations
    def _cmd_ls(self, args: List[str]) -> str:
        """List directory contents"""
        path = '.'
        long_format = False
        show_all = False
        
        # Parse arguments
        for arg in args:
            if arg.startswith('-'):
                if 'l' in arg:
                    long_format = True
                if 'a' in arg:
                    show_all = True
                if 'h' in arg:
                    pass  # Human-readable sizes (simplified)
            elif not arg.startswith('-'):
                path = arg
        
        try:
            contents = self.fs.list_directory(path)
            if not contents:
                return ''
            
            if long_format:
                # Generate detailed listing
                lines = []
                for item in contents:
                    if item.startswith('.') and not show_all:
                        continue
                    
                    # Create fake file entry
                    full_path = self.fs.resolve_path(f"{path}/{item}")
                    fake_file = self.fs.root.get(full_path)
                    
                    if fake_file:
                        lines.append(fake_file.to_stat())
                    else:
                        # Generate default entry
                        lines.append(f"-rw-r--r-- 1 root root {random.randint(100, 100000):>8} {datetime.now().strftime('%b %d %H:%M')} {item}")
                
                return '\r\n'.join(lines) + '\r\n'
            else:
                # Simple listing
                visible = [item for item in contents if not item.startswith('.') or show_all]
                return '  '.join(visible) + '\r\n' if visible else ''
                
        except Exception as e:
            return f"ls: cannot access '{path}': {str(e)}\r\n"
    
    def _cmd_ll(self, args: List[str]) -> str:
        """List in long format (alias for ls -l)"""
        return self._cmd_ls(['-l'] + args)
    
    def _cmd_cd(self, args: List[str]) -> str:
        """Change directory"""
        path = args[0] if args else '~'
        success, error = self.fs.change_directory(path)
        return error + '\r\n' if error else ''
    
    def _cmd_pwd(self, args: List[str]) -> str:
        """Print working directory"""
        return self.fs.get_current_path() + '\r\n'
    
    def _cmd_cat(self, args: List[str]) -> str:
        """Concatenate and print files"""
        if not args:
            return ''
        
        output = []
        for filepath in args:
            if filepath.startswith('-'):
                continue
            
            success, content = self.fs.read_file(filepath)
            if success:
                output.append(content)
            else:
                return content + '\r\n'  # Error message
        
        return '\r\n'.join(output) + '\r\n' if output else ''
    
    def _cmd_head(self, args: List[str]) -> str:
        """Output first part of files"""
        lines = 10
        filepath = None
        
        for arg in args:
            if arg.startswith('-n'):
                lines = int(arg[2:]) if len(arg) > 2 else 10
            elif not arg.startswith('-'):
                filepath = arg
        
        if not filepath:
            return ''
        
        success, content = self.fs.read_file(filepath)
        if success:
            content_lines = content.split('\n')[:lines]
            return '\r\n'.join(content_lines) + '\r\n'
        return content + '\r\n'
    
    def _cmd_tail(self, args: List[str]) -> str:
        """Output last part of files"""
        lines = 10
        filepath = None
        
        for arg in args:
            if arg.startswith('-n'):
                lines = int(arg[2:]) if len(arg) > 2 else 10
            elif not arg.startswith('-'):
                filepath = arg
        
        if not filepath:
            return ''
        
        success, content = self.fs.read_file(filepath)
        if success:
            content_lines = content.split('\n')[-lines:]
            return '\r\n'.join(content_lines) + '\r\n'
        return content + '\r\n'
    
    def _cmd_grep(self, args: List[str]) -> str:
        """Search for patterns"""
        if len(args) < 2:
            return 'Usage: grep [OPTION]... PATTERN [FILE]...\r\n'
        
        pattern = args[0]
        filepath = args[1]
        
        success, content = self.fs.read_file(filepath)
        if success:
            matching_lines = [line for line in content.split('\n') if pattern in line]
            return '\r\n'.join(matching_lines) + '\r\n' if matching_lines else ''
        return content + '\r\n'
    
    def _cmd_find(self, args: List[str]) -> str:
        """Search for files"""
        if not args:
            return ''
        
        # Simplified find - just return some fake results
        fake_results = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/ssh/sshd_config',
            '/root/.bashrc',
            '/root/.ssh/authorized_keys',
            '/var/log/auth.log',
            '/var/log/syslog',
            '/home/admin/.bashrc',
            '/home/user/.bashrc',
            '/tmp/test.conf',
            '/usr/local/etc/config.ini',
        ]
        
        return '\r\n'.join(fake_results) + '\r\n'
    
    def _cmd_ps(self, args: List[str]) -> str:
        """Report process status"""
        processes = [
            '  PID TTY          TIME CMD',
            '    1 ?        00:00:01 systemd',
            '    2 ?        00:00:00 kthreadd',
            '    3 ?        00:00:00 rcu_gp',
            '    4 ?        00:00:00 rcu_par_gp',
            '  500 ?        00:00:05 sshd',
            '  501 ?        00:00:00 systemd-journal',
            '  502 ?        00:00:00 rsyslogd',
            '  503 ?        00:00:00 cron',
            '  504 ?        00:00:00 dbus-daemon',
            '  505 ?        00:00:00 networkd-dispat',
            '  506 ?        00:00:00 unattended-upgr',
            '  507 ?        00:00:00 agetty',
            '  508 ?        00:00:00 agetty',
            '  600 ?        00:00:00 sshd',
            '  601 pts/0    00:00:00 bash',
            '  650 pts/0    00:00:00 ps',
        ]
        return '\r\n'.join(processes) + '\r\n'
    
    def _cmd_whoami(self, args: List[str]) -> str:
        """Print effective userid"""
        return self.username + '\r\n'
    
    def _cmd_id(self, args: List[str]) -> str:
        """Print real and effective user and group IDs"""
        if self.username == 'root':
            return 'uid=0(root) gid=0(root) groups=0(root)\r\n'
        else:
            uid = random.randint(1000, 2000)
            return f'uid={uid}({self.username}) gid={uid}({self.username}) groups={uid}({self.username}),27(sudo)\r\n'
    
    def _cmd_uname(self, args: List[str]) -> str:
        """Print system information"""
        if '-a' in args:
            return 'Linux debian-server 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64 GNU/Linux\r\n'
        elif '-r' in args:
            return '5.10.0-23-amd64\r\n'
        elif '-m' in args:
            return 'x86_64\r\n'
        elif '-n' in args:
            return 'debian-server\r\n'
        elif '-s' in args or not args:
            return 'Linux\r\n'
        return ''
    
    def _cmd_w(self, args: List[str]) -> str:
        """Show who is logged on and what they are doing"""
        output = [
            ' 00:00:01 up 15 days,  3:42,  1 user,  load average: 0.02, 0.05, 0.01',
            'USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU  WHAT',
            f'{self.username}     pts/0    {self.client_ip:<16} 00:00    0.00s  0.02s  0.00s  w'
        ]
        return '\r\n'.join(output) + '\r\n'
    
    def _cmd_last(self, args: List[str]) -> str:
        """Show a listing of last logged in users"""
        entries = [
            f'{self.username}     pts/0        {self.client_ip:<16} {datetime.now().strftime("%a %b %d %H:%M")}   still logged in',
            'admin    pts/0        192.168.1.100    Mon Feb 12 08:30 - 10:45  (02:15)',
            'root     pts/0        10.0.0.50        Sun Feb 11 14:22 - 14:25  (00:03)',
            'deploy   pts/1        172.16.0.10      Sat Feb 10 22:10 - 22:30  (00:20)',
            'reboot   system boot  5.10.0-23-amd64  Fri Feb 09 09:00 - 00:00 (5+15:00)',
        ]
        return '\r\n'.join(entries) + '\r\n'
    
    def _cmd_df(self, args: List[str]) -> str:
        """Report file system disk space usage"""
        output = [
            'Filesystem     1K-blocks     Used Available Use% Mounted on',
            'udev             4096000        0   4096000   0% /dev',
            'tmpfs             819200    10240    808960   2% /run',
            '/dev/sda1      102400000 20480000  81920000  20% /',
            'tmpfs            4096000        0   4096000   0% /dev/shm',
            'tmpfs               5120        0      5120   0% /run/lock',
            '/dev/sdb1      512000000 10240000 501760000   2% /data',
        ]
        return '\r\n'.join(output) + '\r\n'
    
    def _cmd_free(self, args: List[str]) -> str:
        """Display amount of free and used memory"""
        output = [
            '              total        used        free      shared  buff/cache   available',
            'Mem:       8192000     2048000     4096000      102400     2048000     5734400',
            'Swap:      2097148           0     2097148'
        ]
        return '\r\n'.join(output) + '\r\n'
    
    def _cmd_ifconfig(self, args: List[str]) -> str:
        """Configure network interface"""
        output = [
            'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500',
            '        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255',
            '        inet6 fe80::20c:29ff:feb9:7c30  prefixlen 64  scopeid 0x20<link>',
            '        ether 00:0c:29:b9:7c:30  txqueuelen 1000  (Ethernet)',
            '        RX packets 1234567  bytes 1234567890 (1.1 GiB)',
            '        RX errors 0  dropped 0  overruns 0  frame 0',
            '        TX packets 987654  bytes 987654321 (941.5 MiB)',
            '        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0',
            '',
            'lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536',
            '        inet 127.0.0.1  netmask 255.0.0.0',
            '        inet6 ::1  prefixlen 128  scopeid 0x10<host>',
            '        loop  txqueuelen 1000  (Local Loopback)',
            '        RX packets 100000  bytes 8000000 (7.6 MiB)',
            '        RX errors 0  dropped 0  overruns 0  frame 0',
            '        TX packets 100000  bytes 8000000 (7.6 MiB)',
            '        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0'
        ]
        return '\r\n'.join(output) + '\r\n'
    
    def _cmd_ip(self, args: List[str]) -> str:
        """Show/manipulate routing, devices, policy routing and tunnels"""
        if args and args[0] == 'addr':
            return self._cmd_ifconfig(args)
        elif args and args[0] == 'link':
            return '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\r\n'
        elif args and args[0] == 'route':
            return 'default via 192.168.1.1 dev eth0 proto dhcp metric 100\r\n192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100\r\n'
        return ''
    
    def _cmd_netstat(self, args: List[str]) -> str:
        """Print network connections"""
        if '-an' in args or '-tuln' in args:
            connections = [
                'Active Internet connections (servers and established)',
                'Proto Recv-Q Send-Q Local Address           Foreign Address         State',
                'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN',
                'tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN',
                'tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN',
                'tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN',
                'tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN',
                'tcp        0      0 192.168.1.100:22        192.168.1.50:54321      ESTABLISHED',
                'tcp6       0      0 :::22                   :::*                    LISTEN',
                'tcp6       0      0 :::80                   :::*                    LISTEN',
                'udp        0      0 0.0.0.0:68              0.0.0.0:*',
                'udp        0      0 192.168.1.100:123       0.0.0.0:*',
            ]
            return '\r\n'.join(connections) + '\r\n'
        return ''
    
    def _cmd_ss(self, args: List[str]) -> str:
        """Investigate sockets"""
        return self._cmd_netstat(['-tuln'])
    
    def _cmd_hostname(self, args: List[str]) -> str:
        """Show or set system hostname"""
        if args:
            return ''  # Pretend to set hostname
        return 'debian-server\r\n'
    
    def _cmd_echo(self, args: List[str]) -> str:
        """Display a line of text"""
        return ' '.join(args) + '\r\n'
    
    def _cmd_which(self, args: List[str]) -> str:
        """Locate a command"""
        if not args:
            return ''
        
        commands = {
            'bash': '/bin/bash',
            'sh': '/bin/sh',
            'python3': '/usr/bin/python3',
            'python': '/usr/bin/python3',
            'perl': '/usr/bin/perl',
            'ruby': '/usr/bin/ruby',
            'php': '/usr/bin/php',
            'node': '/usr/bin/node',
            'npm': '/usr/bin/npm',
            'git': '/usr/bin/git',
            'docker': '/usr/bin/docker',
            'curl': '/usr/bin/curl',
            'wget': '/usr/bin/wget',
            'ssh': '/usr/bin/ssh',
            'scp': '/usr/bin/scp',
            'vi': '/usr/bin/vi',
            'vim': '/usr/bin/vim',
            'nano': '/usr/bin/nano',
            'cat': '/bin/cat',
            'ls': '/bin/ls',
            'grep': '/bin/grep',
            'awk': '/usr/bin/awk',
            'sed': '/bin/sed',
        }
        
        cmd = args[0]
        if cmd in commands:
            return commands[cmd] + '\r\n'
        return f'\r\n'
    
    def _cmd_history(self, args: List[str]) -> str:
        """Show command history"""
        output = []
        for i, cmd in enumerate(self.command_history[-50:], 1):
            output.append(f' {i:5}  {cmd}')
        return '\r\n'.join(output) + '\r\n' if output else ''
    
    def _cmd_clear(self, args: List[str]) -> str:
        """Clear the terminal screen"""
        return '\033[2J\033[H'
    
    def _cmd_exit(self, args: List[str]) -> str:
        """Exit the shell"""
        self.running = False
        return 'logout\r\n'
    
    def _cmd_wget(self, args: List[str]) -> str:
        """Non-interactive network downloader"""
        url = None
        for arg in args:
            if not arg.startswith('-') and ('http' in arg or 'ftp' in arg):
                url = arg
                break
        
        if url:
            filename = url.split('/')[-1] or 'download'
            return f'''
--{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}--  {url}
           => '{filename}'
Resolving {url.split('/')[2]}... 93.184.216.34
Connecting to {url.split('/')[2]}|93.184.216.34|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12345 (12K)
Saving to: '{filename}'

{filename}          100%[===================>]  12.06K  --.-KB/s    in 0.1s

{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} saved ' {filename}' (12345/12345 bytes in 0.1s)\r\n'''
        return 'wget: missing URL\r\n'
    
    def _cmd_curl(self, args: List[str]) -> str:
        """Transfer data from or to a server"""
        url = None
        for arg in args:
            if not arg.startswith('-') and 'http' in arg:
                url = arg
                break
        
        if url:
            return '''<!DOCTYPE html>
<html>
<head><title>Example Domain</title></head>
<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents.</p>
</div>
</body>
</html>\r\n'''
        return 'curl: try \'curl --help\' for more information\r\n'
    
    def _cmd_apt(self, args: List[str]) -> str:
        """Package manager"""
        if not args:
            return ''
        
        action = args[0]
        if action == 'update':
            return '''Hit:1 http://deb.debian.org/debian bullseye InRelease
Hit:2 http://deb.debian.org/debian bullseye-updates InRelease
Hit:3 http://security.debian.org/debian-security bullseye-security InRelease
Reading package lists... Done\r\n'''
        elif action == 'install':
            pkg = args[1] if len(args) > 1 else 'package'
            return f'''Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  {pkg}
0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
Need to get 123 kB of archives.
After this operation, 456 kB of additional disk space will be used.
Get:1 http://deb.debian.org/debian bullseye/main amd64 {pkg} amd64 1.0-1 [123 kB]
Fetched 123 kB in 0s (1234 kB/s)
Selecting previously unselected package {pkg}.
(Reading database ... 123456 files and directories currently installed.)
Preparing to unpack .../{pkg}_1.0-1_amd64.deb ...
Unpacking {pkg} (1.0-1) ...
Setting up {pkg} (1.0-1) ...
Processing triggers for man-db (2.9.4-2) ...\r\n'''
        return ''
    
    def _cmd_yum(self, args: List[str]) -> str:
        """Yellowdog Updater Modified"""
        return 'bash: yum: command not found\r\n'  # Debian doesn't have yum
    
    def _cmd_systemctl(self, args: List[str]) -> str:
        """Control systemd system and service manager"""
        if not args:
            return ''
        
        action = args[0]
        service = args[1] if len(args) > 1 else ''
        
        if action == 'status':
            return f'''● {service}.service - Example Service
   Loaded: loaded (/lib/systemd/system/{service}.service; enabled; vendor preset: enabled)
   Active: active (running) since Mon 2024-01-15 10:00:00 UTC; 5 days ago
 Main PID: 1234 ({service})
    Tasks: 10 (limit: 4915)
   Memory: 50.0M
   CGroup: /system.slice/{service}.service
           └─1234 /usr/bin/{service}

Jan 15 10:00:00 debian-server systemd[1]: Started Example Service.\r\n'''
        elif action == 'start':
            return ''
        elif action == 'stop':
            return ''
        elif action == 'restart':
            return ''
        elif action == 'list-units':
            return '''UNIT                     LOAD   ACTIVE SUB     DESCRIPTION
sshd.service             loaded active running OpenBSD server daemon
nginx.service            loaded active running A high performance web server
cron.service             loaded active running Regular background program processing daemon
rsyslog.service          loaded active running System logging service\r\n'''
        return ''
    
    def _cmd_service(self, args: List[str]) -> str:
        """Run a System V init script"""
        return self._cmd_systemctl(args)
    
    def _cmd_useradd(self, args: List[str]) -> str:
        """Create a new user"""
        return ''  # Pretend to work
    
    def _cmd_passwd(self, args: List[str]) -> str:
        """Change user password"""
        return 'Changing password for user.\r\nNew password: \r\nRetype new password: \r\npasswd: all authentication tokens updated successfully.\r\n'
    
    def _cmd_chmod(self, args: List[str]) -> str:
        """Change file mode bits"""
        return ''
    
    def _cmd_chown(self, args: List[str]) -> str:
        """Change file owner and group"""
        return ''
    
    def _cmd_rm(self, args: List[str]) -> str:
        """Remove files or directories"""
        return ''
    
    def _cmd_cp(self, args: List[str]) -> str:
        """Copy files and directories"""
        return ''
    
    def _cmd_mv(self, args: List[str]) -> str:
        """Move/rename files"""
        return ''
    
    def _cmd_mkdir(self, args: List[str]) -> str:
        """Make directories"""
        return ''
    
    def _cmd_rmdir(self, args: List[str]) -> str:
        """Remove empty directories"""
        return ''
    
    def _cmd_touch(self, args: List[str]) -> str:
        """Change file timestamps"""
        return ''
    
    def _cmd_ping(self, args: List[str]) -> str:
        """Send ICMP echo requests"""
        host = args[0] if args else '8.8.8.8'
        output = [
            f'PING {host} (8.8.8.8) 56(84) bytes of data.',
            '64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms',
            '64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=14.8 ms',
            '64 bytes from 8.8.8.8: icmp_seq=3 ttl=118 time=15.1 ms',
            '',
            '--- 8.8.8.8 ping statistics ---',
            '3 packets transmitted, 3 received, 0% packet loss, time 2003ms',
            'rtt min/avg/max/mdev = 14.812/15.023/15.234/0.211 ms'
        ]
        return '\r\n'.join(output) + '\r\n'
    
    def _cmd_traceroute(self, args: List[str]) -> str:
        """Print the route packets trace to network host"""
        host = args[0] if args else '8.8.8.8'
        output = [
            f'traceroute to {host} (8.8.8.8), 30 hops max, 60 byte packets',
            ' 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.123 ms  1.045 ms',
            ' 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.543 ms  5.432 ms',
            ' 3  isp-router.isp.net (203.0.113.1)  10.123 ms  9.987 ms  9.876 ms',
            ' 4  core-router.isp.net (198.51.100.1)  15.456 ms  15.345 ms  15.234 ms',
            ' 5  8.8.8.8 (8.8.8.8)  20.789 ms  20.678 ms  20.567 ms'
        ]
        return '\r\n'.join(output) + '\r\n'
    
    def _cmd_nslookup(self, args: List[str]) -> str:
        """Query Internet name servers"""
        host = args[0] if args else 'google.com'
        return f'''Server:\t\t192.168.1.1
Address:\t192.168.1.1#53

Non-authoritative answer:
Name:\t{host}
Address: 142.250.80.46\r\n'''
    
    def _cmd_dig(self, args: List[str]) -> str:
        """DNS lookup utility"""
        return self._cmd_nslookup(args)
    
    def _cmd_python(self, args: List[str]) -> str:
        """Python interpreter"""
        return '''Python 3.9.2 (default, Feb 28 2021, 17:03:44)
[GCC 10.2.1 20210110] :: Anaconda, Inc. on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> \r\n'''
    
    def _cmd_perl(self, args: List[str]) -> str:
        """Perl interpreter"""
        return ''
    
    def _cmd_ruby(self, args: List[str]) -> str:
        """Ruby interpreter"""
        return ''
    
    def _cmd_php(self, args: List[str]) -> str:
        """PHP interpreter"""
        return ''
    
    def _cmd_nc(self, args: List[str]) -> str:
        """Netcat - arbitrary TCP and UDP connections and listens"""
        return ''
    
    def _cmd_nmap(self, args: List[str]) -> str:
        """Network exploration tool and security/port scanner"""
        return ''
    
    def _cmd_ssh(self, args: List[str]) -> str:
        """OpenSSH client"""
        return ''
    
    def _cmd_scp(self, args: List[str]) -> str:
        """Secure copy"""
        return ''
    
    def _cmd_docker(self, args: List[str]) -> str:
        """Docker container platform"""
        if args and args[0] == 'ps':
            return '''CONTAINER ID   IMAGE          COMMAND                  CREATED        STATUS        PORTS                    NAMES
abc123def456   nginx:latest   "/docker-entrypoint.…"   2 weeks ago    Up 2 weeks    0.0.0.0:80->80/tcp       web-server
xyz789uvw012   mysql:8.0      "docker-entrypoint.s…"   3 weeks ago    Up 3 weeks    0.0.0.0:3306->3306/tcp   database\r\n'''
        elif args and args[0] == 'images':
            return '''REPOSITORY          TAG       IMAGE ID       CREATED        SIZE
nginx               latest    abc123def456   2 weeks ago    133MB
mysql               8.0       xyz789uvw012   3 weeks ago    546MB
ubuntu              20.04     def789ghi012   4 weeks ago    72.8MB\r\n'''
        return ''
    
    def _cmd_kubectl(self, args: List[str]) -> str:
        """Kubernetes command-line tool"""
        return 'bash: kubectl: command not found\r\n'
    
    def _cmd_mysql(self, args: List[str]) -> str:
        """MySQL client"""
        return '''Welcome to the MySQL monitor.  Commands end with ; or \\g.
Your MySQL connection id is 12345
Server version: 8.0.32-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type \'help;\' or \'\\h\' for help. Type \'\\c\' to clear the current input statement.

mysql> \r\n'''
    
    def _cmd_psql(self, args: List[str]) -> str:
        """PostgreSQL client"""
        return 'psql (13.9 (Debian 13.9-0+deb11u1))\r\nType "help" for help.\r\n\r\npostgres=# \r\n'
    
    def _cmd_mongo(self, args: List[str]) -> str:
        """MongoDB shell"""
        return 'MongoDB shell version v5.0.14\r\nconnecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb\r\n> \r\n'
    
    def _cmd_redis(self, args: List[str]) -> str:
        """Redis client"""
        return '127.0.0.1:6379> \r\n'
    
    def _cmd_git(self, args: List[str]) -> str:
        """Git version control"""
        if not args:
            return '''usage: git [--version] [--help] [-C <path>] [-c <name>=<value>]
           [--exec-path[=<path>]] [--html-path] [--man-path] [--info-path]
           [-p | --paginate | -P | --no-pager] [--no-replace-objects] [--bare]
           [--git-dir=<path>] [--work-tree=<path>] [--namespace=<name>]
           <command> [<args>]\r\n'''
        
        action = args[0]
        if action == 'clone':
            return 'Cloning into \'repo\'...\r\nremote: Enumerating objects: 100, done.\r\nremote: Counting objects: 100% (100/100), done.\r\nremote: Compressing objects: 100% (50/50), done.\r\nremote: Total 100 (delta 25), reused 100 (delta 25), pack-reused 0\r\nReceiving objects: 100% (100/100), 10.00 KiB | 5.00 MiB/s, done.\r\nResolving deltas: 100% (25/25), done.\r\n'
        elif action == 'status':
            return '''On branch main
Your branch is up to date with \'origin/main\'.

nothing to commit, working tree clean\r\n'''
        elif action == 'log':
            return '''commit abc123def456789012345678901234567890abcd
Author: Admin User <admin@example.com>
Date:   Mon Jan 15 10:00:00 2024 +0000

    Initial commit\r\n'''
        return ''
    
    def _cmd_tar(self, args: List[str]) -> str:
        """Archiving utility"""
        return ''
    
    def _cmd_gzip(self, args: List[str]) -> str:
        """Compression utility"""
        return ''
    
    def _cmd_zip(self, args: List[str]) -> str:
        """Package and compress files"""
        return ''
    
    def _cmd_base64(self, args: List[str]) -> str:
        """Base64 encode/decode"""
        return ''
    
    def _cmd_xxd(self, args: List[str]) -> str:
        """Make a hexdump"""
        return ''
    
    def _cmd_od(self, args: List[str]) -> str:
        """Dump files in octal"""
        return ''
    
    def _cmd_hexdump(self, args: List[str]) -> str:
        """Display file contents in hexadecimal"""
        return ''
    
    def _cmd_openssl(self, args: List[str]) -> str:
        """OpenSSL command line tool"""
        return ''
    
    def _cmd_ssh_keygen(self, args: List[str]) -> str:
        """SSH key generation"""
        return ''
    
    def _cmd_crontab(self, args: List[str]) -> str:
        """Maintain crontab files"""
        if '-l' in args:
            return '# Edit this file to introduce tasks to be run by cron.\r\n'
        return ''
    
    def _cmd_iptables(self, args: List[str]) -> str:
        """Administration tool for IPv4 packet filtering"""
        return ''
    
    def _cmd_ufw(self, args: List[str]) -> str:
        """Uncomplicated Firewall"""
        return ''
    
    def _cmd_dmesg(self, args: List[str]) -> str:
        """Print or control the kernel ring buffer"""
        return '''[    0.000000] Linux version 5.10.0-23-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.179-1 (2023-05-12)
[    0.000000] Command line: BOOT_IMAGE=/vmlinuz-5.10.0-23-amd64 root=/dev/sda1 ro quiet
[    0.000000] KERNEL supported cpus:
[    0.000000]   Intel GenuineIntel
[    0.000000]   AMD AuthenticAMD
[    0.000000]   Centaur CentaurHauls
[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: \'x87 floating point registers\'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x002: \'SSE registers\'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x004: \'AVX registers\'
[    0.000000] x86/fpu: xstate_offset[2]:  576, xstate_sizes[2]:  256\r\n'''
    
    def _cmd_journalctl(self, args: List[str]) -> str:
        """Query the systemd journal"""
        return self._cmd_dmesg(args)
    
    def _cmd_uptime(self, args: List[str]) -> str:
        """Tell how long the system has been running"""
        return ' 00:00:01 up 15 days,  3:42,  1 user,  load average: 0.02, 0.05, 0.01\r\n'
    
    def _cmd_date(self, args: List[str]) -> str:
        """Print or set system date and time"""
        return datetime.now().strftime("%a %b %d %H:%M:%S %Z %Y\r\n")
    
    def _cmd_who(self, args: List[str]) -> str:
        """Show who is logged on"""
        return f'{self.username}     pts/0        {datetime.now().strftime("%Y-%m-%d %H:%M")} ({self.client_ip})\r\n'
    
    def _cmd_users(self, args: List[str]) -> str:
        """Print user names"""
        return f'{self.username}\r\n'
    
    def _cmd_groups(self, args: List[str]) -> str:
        """Print group names"""
        if self.username == 'root':
            return 'root\r\n'
        return f'{self.username} sudo\r\n'
    
    def _cmd_env(self, args: List[str]) -> str:
        """Print environment"""
        env_vars = [
            'SHELL=/bin/bash',
            'USER=' + self.username,
            'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'PWD=' + self.fs.get_current_path(),
            'LANG=en_US.UTF-8',
            'HOME=' + ('/root' if self.username == 'root' else f'/home/{self.username}'),
            'LOGNAME=' + self.username,
            'TERM=xterm-256color',
            'XDG_SESSION_TYPE=tty',
            'XDG_SESSION_CLASS=user',
            'XDG_RUNTIME_DIR=/run/user/0' if self.username == 'root' else f'/run/user/1000',
        ]
        return '\r\n'.join(env_vars) + '\r\n'
    
    def _cmd_export(self, args: List[str]) -> str:
        """Set environment variable"""
        return ''
    
    def _cmd_source(self, args: List[str]) -> str:
        """Execute commands from file"""
        return ''
    
    def _cmd_alias(self, args: List[str]) -> str:
        """Define or display aliases"""
        if not args:
            return '''alias egrep=\'egrep --color=auto\'
alias fgrep=\'fgrep --color=auto\'
alias grep=\'grep --color=auto\'
alias l=\'ls -CF\'
alias la=\'ls -A\'
alias ll=\'ls -alF\'
alias ls=\'ls --color=auto\'\r\n'''
        return ''
    
    def _cmd_unalias(self, args: List[str]) -> str:
        """Remove alias definitions"""
        return ''
    
    def _cmd_type(self, args: List[str]) -> str:
        """Display information about command type"""
        if args:
            return f'{args[0]} is /usr/bin/{args[0]}\r\n'
        return ''
    
    def _cmd_help(self, args: List[str]) -> str:
        """Display information about builtin commands"""
        return 'GNU bash, version 5.1.4(1)-release (x86_64-pc-linux-gnu)\r\nType \'help\' to see this list.\r\n'
    
    def _cmd_man(self, args: List[str]) -> str:
        """Interface to the on-line reference manuals"""
        return 'No manual entry for ' + (args[0] if args else 'command') + '\r\n'
    
    def _cmd_info(self, args: List[str]) -> str:
        """Read Info documents"""
        return ''
    
    def _cmd_whatis(self, args: List[str]) -> str:
        """Display one-line manual page descriptions"""
        return ''
    
    def _cmd_apropos(self, args: List[str]) -> str:
        """Search manual page names and descriptions"""
        return ''
    
    def _cmd_whereis(self, args: List[str]) -> str:
        """Locate binary, source, and manual page files"""
        return ''
    
    def _cmd_locate(self, args: List[str]) -> str:
        """Find files by name"""
        return ''
    
    def _cmd_updatedb(self, args: List[str]) -> str:
        """Update database for mlocate"""
        return ''
    
    def _cmd_su(self, args: List[str]) -> str:
        """Change user ID"""
        return 'Password: \r\n'
    
    def _cmd_sudo(self, args: List[str]) -> str:
        """Execute command as another user"""
        if not args:
            return 'usage: sudo -h | -K | -k | -V\r\n'
        
        # Execute the command with elevated privileges
        command_line = ' '.join(args)
        return self.execute_command(command_line)
    
    def _cmd_mount(self, args: List[str]) -> str:
        """Mount filesystem"""
        return '''sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime,seclabel)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
devtmpfs on /dev type devtmpfs (rw,nosuid,seclabel,size=4096000k,nr_inodes=1024000,mode=755)
/dev/sda1 on / type ext4 (rw,relatime,seclabel)\r\n'''
    
    def _cmd_umount(self, args: List[str]) -> str:
        """Unmount filesystem"""
        return ''
    
    def _cmd_fdisk(self, args: List[str]) -> str:
        """Partition table manipulator"""
        return ''
    
    def _cmd_parted(self, args: List[str]) -> str:
        """Partition manipulation program"""
        return ''
    
    def _cmd_mkfs(self, args: List[str]) -> str:
        """Build Linux filesystem"""
        return ''
    
    def _cmd_fsck(self, args: List[str]) -> str:
        """Check and repair Linux filesystem"""
        return ''
    
    def _cmd_dd(self, args: List[str]) -> str:
        """Convert and copy file"""
        return ''
    
    def _cmd_sync(self, args: List[str]) -> str:
        """Synchronize cached writes"""
        return ''
    
    def _cmd_reboot(self, args: List[str]) -> str:
        """Reboot system"""
        return ''
    
    def _cmd_shutdown(self, args: List[str]) -> str:
        """Shutdown system"""
        return ''
    
    def _cmd_poweroff(self, args: List[str]) -> str:
        """Power off system"""
        return ''
    
    def _cmd_halt(self, args: List[str]) -> str:
        """Halt system"""
        return ''
    
    def _cmd_init(self, args: List[str]) -> str:
        """System V init"""
        return ''
    
    def _cmd_runlevel(self, args: List[str]) -> str:
        """Output previous and current runlevel"""
        return 'N 5\r\n'
    
    def _cmd_kill(self, args: List[str]) -> str:
        """Send signal to process"""
        return ''
    
    def _cmd_killall(self, args: List[str]) -> str:
        """Kill processes by name"""
        return ''
    
    def _cmd_pkill(self, args: List[str]) -> str:
        """Signal process based on name"""
        return ''
    
    def _cmd_pgrep(self, args: List[str]) -> str:
        """Look up processes based on name"""
        return '1234\r\n5678\r\n'
    
    def _cmd_top(self, args: List[str]) -> str:
        """Display Linux processes"""
        return '''top - 00:00:01 up 15 days,  3:42,  1 user,  load average: 0.02, 0.05, 0.01
Tasks: 150 total,   1 running, 149 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   8000.0 total,   4000.0 free,   2000.0 used,   2000.0 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   5600.0 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
    1 root      20   0  168000  12000   8000 S   0.0   0.1   0:01.23 systemd
  500 root      20   0   80000   6000   4000 S   0.0   0.1   0:00.50 sshd\r\n'''
    
    def _cmd_htop(self, args: List[str]) -> str:
        """Interactive process viewer"""
        return self._cmd_top(args)
    
    def _cmd_vmstat(self, args: List[str]) -> str:
        """Report virtual memory statistics"""
        return '''procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
 0  0      0 4096000 200000 2000000    0    0     0     0   10   20  0  0 100  0  0\r\n'''
    
    def _cmd_iostat(self, args: List[str]) -> str:
        """Report CPU and I/O statistics"""
        return '''Linux 5.10.0-23-amd64 (debian-server) \t01/15/2024 \t_x86_64_\t(4 CPU)

avg-cpu:  %user   %nice %system %iowait  %steal   %idle
           0.30    0.00    0.20    0.00    0.00   99.50

Device             tps    kB_read/s    kB_wrtn/s    kB_dscd/s    kB_read    kB_wrtn    kB_dscd
sda               0.50         5.00         3.00         0.00    5000000    3000000          0\r\n'''
    
    def _cmd_mpstat(self, args: List[str]) -> str:
        """Report processors related statistics"""
        return '''Linux 5.10.0-23-amd64 (debian-server) \t01/15/2024 \t_x86_64_\t(4 CPU)

00:00:01 AM  CPU    %usr   %nice    %sys %iowait    %irq   %soft  %steal  %guest  %gnice   %idle
00:00:01 AM  all    0.30    0.00    0.20    0.00    0.00    0.00    0.00    0.00    0.00   99.50\r\n'''
    
    def _cmd_sar(self, args: List[str]) -> str:
        """Collect and report system activity"""
        return ''
    
    def _cmd_pidstat(self, args: List[str]) -> str:
        """Report statistics for Linux tasks"""
        return ''
    
    def _cmd_tload(self, args: List[str]) -> str:
        """Graphic representation of system load average"""
        return ''
    
    def _cmd_watch(self, args: List[str]) -> str:
        """Execute program periodically"""
        return ''
    
    def _cmd_screen(self, args: List[str]) -> str:
        """Terminal multiplexer"""
        return ''
    
    def _cmd_tmux(self, args: List[str]) -> str:
        """Terminal multiplexer"""
        return ''
    
    def _cmd_nohup(self, args: List[str]) -> str:
        """Run command immune to hangups"""
        return ''
    
    def _cmd_disown(self, args: List[str]) -> str:
        """Remove jobs from current shell"""
        return ''
    
    def _cmd_jobs(self, args: List[str]) -> str:
        """List active jobs"""
        return ''
    
    def _cmd_fg(self, args: List[str]) -> str:
        """Place job in foreground"""
        return ''
    
    def _cmd_bg(self, args: List[str]) -> str:
        """Place job in background"""
        return ''
    
    def _cmd_nice(self, args: List[str]) -> str:
        """Run program with modified scheduling priority"""
        return ''
    
    def _cmd_renice(self, args: List[str]) -> str:
        """Alter priority of running processes"""
        return ''
    
    def _cmd_time(self, args: List[str]) -> str:
        """Time command execution"""
        return ''
    
    def _cmd_timeout(self, args: List[str]) -> str:
        """Run command with time limit"""
        return ''
    
    def _cmd_chroot(self, args: List[str]) -> str:
        """Run command with different root directory"""
        return ''
    
    def _cmd_ldd(self, args: List[str]) -> str:
        """Print shared library dependencies"""
        return ''
    
    def _cmd_ldconfig(self, args: List[str]) -> str:
        """Configure dynamic linker run-time bindings"""
        return ''
    
    def _cmd_locale(self, args: List[str]) -> str:
        """Get locale-specific information"""
        return '''LANG=en_US.UTF-8
LANGUAGE=
LC_CTYPE="en_US.UTF-8"
LC_NUMERIC="en_US.UTF-8"
LC_TIME="en_US.UTF-8"
LC_COLLATE="en_US.UTF-8"
LC_MONETARY="en_US.UTF-8"
LC_MESSAGES="en_US.UTF-8"
LC_PAPER="en_US.UTF-8"
LC_NAME="en_US.UTF-8"
LC_ADDRESS="en_US.UTF-8"
LC_TELEPHONE="en_US.UTF-8"
LC_MEASUREMENT="en_US.UTF-8"
LC_IDENTIFICATION="en_US.UTF-8"
LC_ALL=\r\n'''
    
    def _cmd_localedef(self, args: List[str]) -> str:
        """Compile locale definition files"""
        return ''
    
    def _cmd_tzselect(self, args: List[str]) -> str:
        """Select timezone"""
        return ''
    
    def _cmd_tzconfig(self, args: List[str]) -> str:
        """Configure timezone"""
        return ''
    
    def _cmd_hwclock(self, args: List[str]) -> str:
        """Query and set hardware clock"""
        return ''
    
    def _cmd_timedatectl(self, args: List[str]) -> str:
        """Control system time and date"""
        return '''               Local time: Mon 2024-01-15 00:00:01 UTC
           Universal time: Mon 2024-01-15 00:00:01 UTC
                 RTC time: Mon 2024-01-15 00:00:01
                Time zone: UTC (UTC, +0000)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no\r\n'''
    
    def _cmd_hostnamectl(self, args: List[str]) -> str:
        """Control system hostname"""
        return '''   Static hostname: debian-server
         Icon name: computer-vm
           Chassis: vm
        Machine ID: abc123def45678901234567890123456
           Boot ID: xyz789uvw01234567890123456789012
    Virtualization: kvm
  Operating System: Debian GNU/Linux 11 (bullseye)
            Kernel: Linux 5.10.0-23-amd64
      Architecture: x86-64\r\n'''
    
    def _cmd_localectl(self, args: List[str]) -> str:
        """Control system locale and keyboard layout"""
        return '''   System Locale: LANG=en_US.UTF-8
       VC Keymap: n/a
      X11 Layout: us
       X11 Model: pc105\r\n'''
    
    def _cmd_loginctl(self, args: List[str]) -> str:
        """Control systemd login manager"""
        return '''SESSION  UID USER   SEAT  TTY  
      1 1000 admin  seat0 pts/0

1 sessions listed.\r\n'''
    
    def _cmd_machinectl(self, args: List[str]) -> str:
        """Control systemd machines"""
        return ''
    
    def _cmd_busctl(self, args: List[str]) -> str:
        """Introspect D-Bus"""
        return ''
    
    def _cmd_systemd_analyze(self, args: List[str]) -> str:
        """Analyze systemd"""
        return 'Startup finished in 2.345s (kernel) + 1.234s (initrd) + 5.678s (userspace) = 9.257s\r\n'
    
    def _cmd_systemd_cgtop(self, args: List[str]) -> str:
        """Show top control groups"""
        return ''
    
    def _cmd_systemd_cgls(self, args: List[str]) -> str:
        """Show cgroup hierarchy"""
        return ''
    
    def _cmd_systemd_resolve(self, args: List[str]) -> str:
        """Resolve domain names"""
        return ''
    
    def _cmd_systemd_delta(self, args: List[str]) -> str:
        """Find overridden configuration files"""
        return ''
    
    def _cmd_systemd_detect_virt(self, args: List[str]) -> str:
        """Detect execution environment"""
        return 'kvm\r\n'
    
    def _cmd_systemd_escape(self, args: List[str]) -> str:
        """Escape strings for systemd"""
        return ''
    
    def _cmd_systemd_path(self, args: List[str]) -> str:
        """List/search paths"""
        return ''
    
    def _cmd_systemd_run(self, args: List[str]) -> str:
        """Run programs in transient scope or service"""
        return ''
    
    def _cmd_systemd_inhibit(self, args: List[str]) -> str:
        """Execute program with inhibit lock"""
        return ''
    
    def _cmd_systemd_tmpfiles(self, args: List[str]) -> str:
        """Create, delete, clean up volatile and temporary files"""
        return ''
    
    def _cmd_systemd_sysusers(self, args: List[str]) -> str:
        """ Allocate system users and groups"""
        return ''
    
    def _cmd_systemd_machine_id_setup(self, args: List[str]) -> str:
        """Initialize machine ID in /etc/machine-id"""
        return ''
    
    def run(self):
        """Main shell loop"""
        try:
            self.send_welcome()
            
            while self.running:
                # Send prompt
                self.send(self.get_prompt())
                
                # Read command line
                command_line = ''
                while True:
                    char = self.recv(1)
                    
                    if not char:
                        self.running = False
                        break
                    
                    # Handle special characters
                    if char == '\r' or char == '\n':
                        self.send('\r\n')
                        break
                    elif char == '\x7f' or char == '\x08':  # Backspace
                        if command_line:
                            command_line = command_line[:-1]
                            self.send('\x08 \x08')
                    elif char == '\x03':  # Ctrl+C
                        self.send('^C\r\n')
                        command_line = ''
                        break
                    elif char == '\x04':  # Ctrl+D
                        if not command_line:
                            self.running = False
                            break
                    elif char == '\x15':  # Ctrl+U (clear line)
                        self.send('\r' + ' ' * len(command_line) + '\r')
                        command_line = ''
                    elif char == '\x0c':  # Ctrl+L (clear screen)
                        self.send('\033[2J\033[H')
                    elif ord(char) >= 32:  # Printable characters
                        command_line += char
                        self.send(char)
                
                if not self.running:
                    break
                
                if command_line.strip():
                    # Execute command
                    output = self.execute_command(command_line)
                    if output:
                        self.send(output)
            
        except Exception as e:
            import logging
            logging.error(f"Shell error: {e}")
        finally:
            try:
                self.channel.close()
            except:
                pass


def random_duration():
    """Generate a random time duration for fake login history"""
    from datetime import timedelta
    import random
    return timedelta(
        days=random.randint(0, 30),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59)
    )
