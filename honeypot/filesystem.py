#!/usr/bin/env python3
"""
Fake Filesystem - Simulates a realistic Debian Linux environment
"""

import os
import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path


class FakeFile:
    """Represents a file in the fake filesystem"""
    
    def __init__(self, name: str, content: str = "", 
                 owner: str = "root", group: str = "root",
                 permissions: int = 0o644, is_directory: bool = False,
                 size: Optional[int] = None):
        self.name = name
        self.content = content
        self.owner = owner
        self.group = group
        self.permissions = permissions
        self.is_directory = is_directory
        self.size = size if size is not None else len(content)
        self.created = datetime.now() - timedelta(days=random.randint(30, 365))
        self.modified = self.created + timedelta(days=random.randint(0, 30))
        self.accessed = self.modified
        
    def to_stat(self) -> str:
        """Generate stat-like output"""
        perms = self._format_permissions()
        size_str = str(self.size) if not self.is_directory else "4096"
        date_str = self.modified.strftime("%b %d %H:%M")
        return f"{perms} 1 {self.owner:8} {self.group:8} {size_str:>8} {date_str} {self.name}"
    
    def _format_permissions(self) -> str:
        """Format permissions in ls -l style"""
        type_char = 'd' if self.is_directory else '-'
        
        # Owner permissions
        owner = self._perm_bits_to_str((self.permissions >> 6) & 0o7)
        # Group permissions
        group = self._perm_bits_to_str((self.permissions >> 3) & 0o7)
        # Other permissions
        other = self._perm_bits_to_str(self.permissions & 0o7)
        
        return f"{type_char}{owner}{group}{other}"
    
    def _perm_bits_to_str(self, bits: int) -> str:
        """Convert permission bits to rwx string"""
        result = ""
        result += 'r' if bits & 0o4 else '-'
        result += 'w' if bits & 0o2 else '-'
        result += 'x' if bits & 0o1 else '-'
        return result


class FakeFilesystem:
    """Simulates a complete Debian filesystem"""
    
    def __init__(self):
        self.root = {}
        self.current_path = "/root"
        self._init_filesystem()
        
    def _init_filesystem(self):
        """Initialize realistic Debian filesystem structure"""
        
        # Root directory structure
        self.root = {
            '/': self._create_directory('/', [
                'bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib64',
                'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin',
                'srv', 'sys', 'tmp', 'usr', 'var'
            ]),
            
            # /etc directory with realistic files
            '/etc': self._create_directory('/etc', [
                'apt', 'bash.bashrc', 'cron.d', 'cron.daily', 'cron.hourly',
                'cron.monthly', 'cron.weekly', 'crontab', 'fstab', 'group',
                'gshadow', 'host.conf', 'hostname', 'hosts', 'init.d',
                'inittab', 'issue', 'issue.net', 'ld.so.cache', 'ld.so.conf',
                'localtime', 'login.defs', 'magic', 'mailcap.order', 'modprobe.d',
                'modules', 'motd', 'mtab', 'networks', 'nsswitch.conf',
                'os-release', 'passwd', 'profile', 'protocols', 'resolv.conf',
                'rpc', 'securetty', 'services', 'shadow', 'shells',
                'skel', 'ssh', 'ssl', 'sysctl.conf', 'syslog.conf',
                'terminfo', 'timezone', 'udev', 'vim', 'wgetrc'
            ]),
            
            # /etc/passwd content
            '/etc/passwd': FakeFile(
                'passwd',
                content=self._generate_passwd_content(),
                permissions=0o644
            ),
            
            # /etc/shadow (looks real but has fake hashes)
            '/etc/shadow': FakeFile(
                'shadow',
                content=self._generate_shadow_content(),
                permissions=0o640
            ),
            
            # /etc/os-release
            '/etc/os-release': FakeFile(
                'os-release',
                content='''PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
''',
                permissions=0o644
            ),
            
            # /etc/hostname
            '/etc/hostname': FakeFile(
                'hostname',
                content='debian-server\n',
                permissions=0o644
            ),
            
            # /etc/hosts
            '/etc/hosts': FakeFile(
                'hosts',
                content='''127.0.0.1       localhost
127.0.1.1       debian-server
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
''',
                permissions=0o644
            ),
            
            # /etc/issue
            '/etc/issue': FakeFile(
                'issue',
                content='''Debian GNU/Linux 11 \\n \\l

''',
                permissions=0o644
            ),
            
            # /etc/motd
            '/etc/motd': FakeFile(
                'motd',
                content='''
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
''',
                permissions=0o644
            ),
            
            # /etc/ssh directory
            '/etc/ssh': self._create_directory('/etc/ssh', [
                'moduli', 'ssh_config', 'sshd_config', 'ssh_host_dsa_key',
                'ssh_host_dsa_key.pub', 'ssh_host_ecdsa_key', 'ssh_host_ecdsa_key.pub',
                'ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub',
                'ssh_host_rsa_key', 'ssh_host_rsa_key.pub'
            ]),
            
            # /etc/ssh/sshd_config
            '/etc/ssh/sshd_config': FakeFile(
                'sshd_config',
                content='''# Package generated configuration file
# See the sshd_config(5) manpage for details

Port 22
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
''',
                permissions=0o644
            ),
            
            # /root directory
            '/root': self._create_directory('/root', [
                '.bashrc', '.bash_logout', '.profile', '.ssh', '.vimrc',
                'documents', 'scripts', 'downloads', 'backup.tar.gz'
            ]),
            
            # /root/.bashrc
            '/root/.bashrc': FakeFile(
                '.bashrc',
                content='''# ~/.bashrc: executed by bash(1) for non-login shells.

# Note: PS1 and umask are already set in /etc/profile. You should not
# need this unless you want different defaults for root.
PS1='\\u@\\h:\\w\\$ '
umask 022

# You may uncomment the following lines if you want `ls' to be colorized:
export LS_OPTIONS='--color=auto'
eval "`dircolors`"
alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
alias l='ls $LS_OPTIONS -lA'

# Some more alias to avoid making mistakes:
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
''',
                permissions=0o644
            ),
            
            # /root/.ssh directory
            '/root/.ssh': self._create_directory('/root/.ssh', [
                'authorized_keys', 'id_rsa', 'id_rsa.pub', 'known_hosts'
            ]),
            
            # /root/.ssh/authorized_keys
            '/root/.ssh/authorized_keys': FakeFile(
                'authorized_keys',
                content='''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDuQ... admin@company-laptop
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZ7Z8Z9Z0Z1Z2Z3Z4... deploy@ci-server
''',
                permissions=0o600
            ),
            
            # /root/documents
            '/root/documents': self._create_directory('/root/documents', [
                'readme.txt', 'config.ini', 'data.csv', 'notes.md'
            ]),
            
            # /root/scripts
            '/root/scripts': self._create_directory('/root/scripts', [
                'backup.sh', 'deploy.sh', 'monitor.py', 'cleanup.sh'
            ]),
            
            # /root/scripts/backup.sh
            '/root/scripts/backup.sh': FakeFile(
                'backup.sh',
                content='''#!/bin/bash
# Backup script
BACKUP_DIR="/backup"
SOURCE_DIR="/data"
DATE=$(date +%Y%m%d)

tar -czf "$BACKUP_DIR/backup_$DATE.tar.gz" "$SOURCE_DIR"
echo "Backup completed: backup_$DATE.tar.gz"
''',
                permissions=0o755
            ),
            
            # /root/scripts/deploy.sh
            '/root/scripts/deploy.sh': FakeFile(
                'deploy.sh',
                content='''#!/bin/bash
# Deployment script
APP_DIR="/var/www/app"
GIT_REPO="https://github.com/company/app.git"

cd "$APP_DIR"
git pull origin main
systemctl restart app
systemctl status app
''',
                permissions=0o755
            ),
            
            # /bin directory (common commands)
            '/bin': self._create_directory('/bin', [
                'bash', 'cat', 'chmod', 'chown', 'cp', 'date', 'dd', 'df',
                'dir', 'echo', 'false', 'grep', 'gunzip', 'gzexe', 'gzip',
                'ln', 'ls', 'mkdir', 'mknod', 'mktemp', 'more', 'mv',
                'pwd', 'rm', 'rmdir', 'sed', 'sh', 'sleep', 'stty',
                'su', 'sync', 'tar', 'touch', 'true', 'uname', 'vdir',
                'watch', 'wc', 'which', 'zcat'
            ]),
            
            # /usr/bin directory
            '/usr/bin': self._create_directory('/usr/bin', [
                'awk', 'curl', 'docker', 'git', 'htop', 'nano', 'nc',
                'netstat', 'nginx', 'node', 'npm', 'passwd', 'ping',
                'pip3', 'ps', 'python3', 'scp', 'sftp', 'ssh', 'sudo',
                'systemctl', 'top', 'vi', 'vim', 'wget', 'whoami'
            ]),
            
            # /sbin directory
            '/sbin': self._create_directory('/sbin', [
                'fdisk', 'fsck', 'getty', 'halt', 'ifconfig', 'init',
                'insmod', 'iptables', 'kmod', 'mke2fs', 'mkfs', 'modprobe',
                'poweroff', 'reboot', 'route', 'runlevel', 'shutdown',
                'sshd', 'start-stop-daemon', 'swapoff', 'swapon', 'sysctl'
            ]),
            
            # /var directory
            '/var': self._create_directory('/var', [
                'backups', 'cache', 'lib', 'local', 'lock', 'log',
                'mail', 'opt', 'run', 'spool', 'tmp', 'www'
            ]),
            
            # /var/log directory
            '/var/log': self._create_directory('/var/log', [
                'alternatives.log', 'apt', 'auth.log', 'btmp', 'daemon.log',
                'debug', 'dpkg.log', 'faillog', 'kern.log', 'lastlog',
                'mail.log', 'messages', 'syslog', 'wtmp'
            ]),
            
            # /var/log/auth.log (fake entries)
            '/var/log/auth.log': FakeFile(
                'auth.log',
                content=self._generate_auth_log(),
                permissions=0o640
            ),
            
            # /var/log/syslog (fake entries)
            '/var/log/syslog': FakeFile(
                'syslog',
                content=self._generate_syslog(),
                permissions=0o640
            ),
            
            # /proc directory (virtual filesystem)
            '/proc': self._create_directory('/proc', [
                '1', 'acpi', 'asound', 'buddyinfo', 'bus', 'cgroups',
                'cmdline', 'consoles', 'cpuinfo', 'crypto', 'devices',
                'diskstats', 'dma', 'driver', 'execdomains', 'fb',
                'filesystems', 'fs', 'interrupts', 'iomem', 'ioports',
                'irq', 'kallsyms', 'kcore', 'keys', 'key-users',
                'kmsg', 'kpagecount', 'kpageflags', 'loadavg', 'locks',
                'mdstat', 'meminfo', 'misc', 'modules', 'mounts',
                'mtrr', 'net', 'pagetypeinfo', 'partitions', 'sched_debug',
                'scsi', 'self', 'slabinfo', 'softirqs', 'stat',
                'swaps', 'sys', 'sysrq-trigger', 'sysvipc', 'thread-self',
                'timer_list', 'tty', 'uptime', 'version', 'vmallocinfo',
                'vmstat', 'zoneinfo'
            ]),
            
            # /proc/cpuinfo
            '/proc/cpuinfo': FakeFile(
                'cpuinfo',
                content=self._generate_cpuinfo(),
                permissions=0o444
            ),
            
            # /proc/meminfo
            '/proc/meminfo': FakeFile(
                'meminfo',
                content=self._generate_meminfo(),
                permissions=0o444
            ),
            
            # /proc/uptime
            '/proc/uptime': FakeFile(
                'uptime',
                content=f"{random.randint(100000, 10000000)}.00 {random.randint(100000, 10000000)}.00\n",
                permissions=0o444
            ),
            
            # /proc/version
            '/proc/version': FakeFile(
                'version',
                content='Linux version 5.10.0-23-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.179-1 (2023-05-12)\n',
                permissions=0o444
            ),
            
            # /proc/loadavg
            '/proc/loadavg': FakeFile(
                'loadavg',
                content=f"{random.uniform(0.1, 2.0):.2f} {random.uniform(0.1, 2.0):.2f} {random.uniform(0.1, 2.0):.2f} 1/{random.randint(100, 500)} {random.randint(10000, 99999)}\n",
                permissions=0o444
            ),
            
            # /tmp directory
            '/tmp': self._create_directory('/tmp', [
                '.X11-unix', '.ICE-unix', 'systemd-private-', 'ssh-'
            ]),
            
            # /home directory with fake users
            '/home': self._create_directory('/home', [
                'admin', 'deploy', 'developer', 'user'
            ]),
            
            # /home/admin
            '/home/admin': self._create_directory('/home/admin', [
                '.bashrc', '.profile', 'documents', 'workspace'
            ]),
            
            # /home/user
            '/home/user': self._create_directory('/home/user', [
                '.bashrc', '.profile', 'Downloads', 'Documents', 'Desktop'
            ]),
        }
        
    def _create_directory(self, path: str, contents: List[str]) -> FakeFile:
        """Create a directory FakeFile"""
        return FakeFile(
            name=os.path.basename(path) or '/',
            is_directory=True,
            permissions=0o755,
            content='\n'.join(contents)
        )
    
    def _generate_passwd_content(self) -> str:
        """Generate realistic /etc/passwd content"""
        users = [
            ('root', 0, 0, '/root', '/bin/bash'),
            ('daemon', 1, 1, '/usr/sbin', '/usr/sbin/nologin'),
            ('bin', 2, 2, '/bin', '/usr/sbin/nologin'),
            ('sys', 3, 3, '/dev', '/usr/sbin/nologin'),
            ('sync', 4, 65534, '/bin', '/bin/sync'),
            ('games', 5, 60, '/usr/games', '/usr/sbin/nologin'),
            ('man', 6, 12, '/var/cache/man', '/usr/sbin/nologin'),
            ('lp', 7, 7, '/var/spool/lpd', '/usr/sbin/nologin'),
            ('mail', 8, 8, '/var/mail', '/usr/sbin/nologin'),
            ('news', 9, 9, '/var/spool/news', '/usr/sbin/nologin'),
            ('uucp', 10, 10, '/var/spool/uucp', '/usr/sbin/nologin'),
            ('proxy', 13, 13, '/bin', '/usr/sbin/nologin'),
            ('www-data', 33, 33, '/var/www', '/usr/sbin/nologin'),
            ('backup', 34, 34, '/var/backups', '/usr/sbin/nologin'),
            ('list', 38, 38, '/var/list', '/usr/sbin/nologin'),
            ('irc', 39, 39, '/var/run/ircd', '/usr/sbin/nologin'),
            ('gnats', 41, 41, '/var/lib/gnats', '/usr/sbin/nologin'),
            ('nobody', 65534, 65534, '/nonexistent', '/usr/sbin/nologin'),
            ('_apt', 100, 65534, '/nonexistent', '/usr/sbin/nologin'),
            ('systemd-timesync', 101, 102, '/run/systemd', '/usr/sbin/nologin'),
            ('systemd-network', 102, 103, '/run/systemd', '/usr/sbin/nologin'),
            ('systemd-resolve', 103, 104, '/run/systemd', '/usr/sbin/nologin'),
            ('messagebus', 104, 110, '/nonexistent', '/usr/sbin/nologin'),
            ('sshd', 105, 65534, '/run/sshd', '/usr/sbin/nologin'),
            ('admin', 1000, 1000, '/home/admin', '/bin/bash'),
            ('deploy', 1001, 1001, '/home/deploy', '/bin/bash'),
            ('developer', 1002, 1002, '/home/developer', '/bin/bash'),
            ('user', 1003, 1003, '/home/user', '/bin/bash'),
        ]
        
        lines = []
        for username, uid, gid, home, shell in users:
            # Generate fake password hash prefix
            password = 'x'
            lines.append(f"{username}:{password}:{uid}:{gid}:{username}:{home}:{shell}")
        
        return '\n'.join(lines) + '\n'
    
    def _generate_shadow_content(self) -> str:
        """Generate realistic /etc/shadow content with fake hashes"""
        users = [
            ('root', '$6$rounds=5000$saltsalt$fakehash1234567890abcdef'),
            ('daemon', '*'),
            ('bin', '*'),
            ('sys', '*'),
            ('sync', '*'),
            ('games', '*'),
            ('man', '*'),
            ('lp', '*'),
            ('mail', '*'),
            ('news', '*'),
            ('uucp', '*'),
            ('proxy', '*'),
            ('www-data', '*'),
            ('backup', '*'),
            ('list', '*'),
            ('irc', '*'),
            ('gnats', '*'),
            ('nobody', '*'),
            ('_apt', '*'),
            ('systemd-timesync', '*'),
            ('systemd-network', '*'),
            ('systemd-resolve', '*'),
            ('messagebus', '*'),
            ('sshd', '*'),
            ('admin', '$6$rounds=5000$saltsalt$fakehash0987654321fedcba'),
            ('deploy', '$6$rounds=5000$saltsalt$fakehashabcdef1234567890'),
            ('developer', '$6$rounds=5000$saltsalt$fakehashfedcba0987654321'),
            ('user', '$6$rounds=5000$saltsalt$fakehash5678901234abcdef'),
        ]
        
        lines = []
        for username, password in users:
            last_change = random.randint(18000, 19000)  # Days since epoch
            min_days = 0
            max_days = 99999
            warn_days = 7
            inactive = ''
            expire = ''
            reserved = ''
            
            lines.append(f"{username}:{password}:{last_change}:{min_days}:{max_days}:{warn_days}:{inactive}:{expire}:{reserved}")
        
        return '\n'.join(lines) + '\n'
    
    def _generate_auth_log(self) -> str:
        """Generate fake auth.log entries"""
        lines = []
        base_time = datetime.now() - timedelta(days=7)
        
        for i in range(50):
            timestamp = base_time + timedelta(hours=i*3)
            time_str = timestamp.strftime("%b %d %H:%M:%S")
            
            entries = [
                f"{time_str} debian-server sshd[{random.randint(1000, 9999)}]: Accepted password for admin from 192.168.1.{random.randint(2, 254)} port {random.randint(10000, 65000)} ssh2",
                f"{time_str} debian-server sshd[{random.randint(1000, 9999)}]: pam_unix(sshd:session): session opened for user admin(uid=1000) by (uid=0)",
                f"{time_str} debian-server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
                f"{time_str} debian-server sshd[{random.randint(1000, 9999)}]: pam_unix(sshd:session): session closed for user admin",
            ]
            lines.extend(entries)
        
        return '\n'.join(lines) + '\n'
    
    def _generate_syslog(self) -> str:
        """Generate fake syslog entries"""
        lines = []
        base_time = datetime.now() - timedelta(days=7)
        
        for i in range(100):
            timestamp = base_time + timedelta(hours=i)
            time_str = timestamp.strftime("%b %d %H:%M:%S")
            
            entries = [
                f"{time_str} debian-server systemd[1]: Started Session {random.randint(1, 100)} of user admin.",
                f"{time_str} debian-server kernel: [    0.000000] Linux version 5.10.0-23-amd64",
                f"{time_str} debian-server CRON[{random.randint(1000, 9999)}]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)",
                f"{time_str} debian-server systemd[1]: Starting Daily apt download activities...",
                f"{time_str} debian-server systemd[1]: Finished Daily apt download activities.",
            ]
            lines.extend(entries)
        
        return '\n'.join(lines) + '\n'
    
    def _generate_cpuinfo(self) -> str:
        """Generate fake /proc/cpuinfo"""
        return '''processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 142
model name\t: Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz
stepping\t: 12
microcode\t: 0xde
cpu MHz\t\t: 1992.000
cache size\t: 8192 KB
physical id\t: 0
siblings\t: 4
core id\t\t: 0
cpu cores\t: 4
apicid\t\t: 0
initial apicid\t: 0
fpu\t\t: yes
fpu_exception\t: yes
cpuid level\t: 22
wp\t\t: yes
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single ssbd ibrs ibpb stibp ibrs_enhanced tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d arch_capabilities
vmx flags\t: vnmi preemption_timer invvpid ept_x_only ept_ad ept_1gb flexpriority tsc_offset vtpr mtf vapic ept vpid unrestricted_guest ple shadow_vmcs pml ept_mode_based_exec
bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit srbds mmio_stale_data retbleed gds
bogomips\t: 3999.93
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 39 bits physical, 48 bits virtual
power management:

'''
    
    def _generate_meminfo(self) -> str:
        """Generate fake /proc/meminfo"""
        total_mem = 8192000  # ~8GB in KB
        free_mem = random.randint(1000000, 3000000)
        available_mem = free_mem + random.randint(500000, 1500000)
        buffers = random.randint(100000, 300000)
        cached = random.randint(1000000, 3000000)
        
        return f'''MemTotal:        {total_mem} kB
MemFree:          {free_mem} kB
MemAvailable:     {available_mem} kB
Buffers:          {buffers} kB
Cached:          {cached} kB
SwapCached:            0 kB
Active:          {random.randint(1000000, 4000000)} kB
Inactive:        {random.randint(500000, 2000000)} kB
Active(anon):    {random.randint(500000, 2000000)} kB
Inactive(anon):   {random.randint(100000, 500000)} kB
Active(file):    {random.randint(500000, 2000000)} kB
Inactive(file):  {random.randint(300000, 1500000)} kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
Dirty:               100 kB
Writeback:             0 kB
AnonPages:       {random.randint(500000, 2000000)} kB
Mapped:          {random.randint(200000, 800000)} kB
Shmem:            {random.randint(50000, 200000)} kB
KReclaimable:    {random.randint(100000, 400000)} kB
Slab:            {random.randint(150000, 500000)} kB
SReclaimable:    {random.randint(100000, 400000)} kB
SUnreclaim:       {random.randint(50000, 150000)} kB
KernelStack:       {random.randint(5000, 15000)} kB
PageTables:       {random.randint(20000, 60000)} kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:     6193148 kB
Committed_AS:    {random.randint(2000000, 6000000)} kB
VmallocTotal:   34359738367 kB
VmallocUsed:       {random.randint(30000, 80000)} kB
VmallocChunk:          0 kB
Percpu:            {random.randint(5000, 15000)} kB
HardwareCorrupted:     0 kB
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
ShmemPmdMapped:        0 kB
FileHugePages:         0 kB
FilePmdMapped:         0 kB
HugePages_Total:       0
HugePages_Free:        0
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:               0 kB
DirectMap4k:      {random.randint(200000, 400000)} kB
DirectMap2M:     {random.randint(4000000, 8000000)} kB
DirectMap1G:     {random.randint(0, 4000000)} kB
'''
    
    def resolve_path(self, path: str) -> str:
        """Resolve a path to absolute form"""
        if path.startswith('/'):
            return os.path.normpath(path)
        else:
            return os.path.normpath(os.path.join(self.current_path, path))
    
    def get_file(self, path: str) -> Optional[FakeFile]:
        """Get a file by path"""
        abs_path = self.resolve_path(path)
        return self.root.get(abs_path)
    
    def list_directory(self, path: str = None) -> List[str]:
        """List contents of a directory"""
        if path is None:
            path = self.current_path
        
        abs_path = self.resolve_path(path)
        dir_file = self.root.get(abs_path)
        
        if dir_file and dir_file.is_directory:
            return dir_file.content.split('\n') if dir_file.content else []
        return []
    
    def change_directory(self, path: str) -> Tuple[bool, str]:
        """Change current directory"""
        abs_path = self.resolve_path(path)
        dir_file = self.root.get(abs_path)
        
        if dir_file is None:
            return False, f"bash: cd: {path}: No such file or directory"
        
        if not dir_file.is_directory:
            return False, f"bash: cd: {path}: Not a directory"
        
        self.current_path = abs_path
        return True, ""
    
    def read_file(self, path: str) -> Tuple[bool, str]:
        """Read file contents"""
        abs_path = self.resolve_path(path)
        file = self.root.get(abs_path)
        
        if file is None:
            return False, f"cat: {path}: No such file or directory"
        
        if file.is_directory:
            return False, f"cat: {path}: Is a directory"
        
        return True, file.content
    
    def get_current_path(self) -> str:
        """Get current working directory"""
        return self.current_path
    
    def file_exists(self, path: str) -> bool:
        """Check if file exists"""
        return self.get_file(path) is not None
