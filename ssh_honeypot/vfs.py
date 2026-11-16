# -*- coding: utf-8 -*-
"""
SSH 蜜罐 - 虚拟文件系统定义
"""
import copy

# === 虚拟文件系统定义 ===
VIRTUAL_FS = {
    '/': ['bin', 'boot', 'cdrom', 'dev', 'etc', 'home', 'lib', 'lib32', 'lib64', 'libx32', 'lost+found', 'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'snap', 'srv', 'swapfile', 'sys', 'tmp', 'usr', 'var'],
    '/lost+found': [],
    '/root': ['.bashrc', '.bash_history', '.ssh', 'secret.txt', 'backup.tar.gz'],
    '/root/.ssh': ['id_rsa', 'id_rsa.pub', 'authorized_keys', 'known_hosts'],

    # /bin（高仿真命令集，覆盖常见系统工具与链接命令）
    '/bin': [
        # Shell 与核心命令
        'bash', 'dash', 'sh', 'rbash',
        # 核心工具集
        'cat', 'chgrp', 'chmod', 'chown', 'cp', 'date', 'dd', 'df', 'dir', 'echo', 'false', 'ln', 'ls', 'mkdir', 'mknod', 'mktemp', 'more', 'mv', 'pwd', 'readlink', 'rm', 'rmdir', 'sleep', 'stat', 'stty', 'sync', 'touch', 'true', 'uname', 'vdir',
        # 文本处理
        'base64', 'basename', 'cat', 'cut', 'dirname', 'expr', 'fmt', 'head', 'join', 'md5sum', 'nl', 'od', 'paste', 'pr', 'seq', 'sha1sum', 'sha256sum', 'sort', 'split', 'tail', 'tee', 'tr', 'uniq', 'wc',
        # grep 相关工具（含兼容链接）
        'egrep', 'fgrep', 'grep', 'zcat', 'zgrep', 'zless', 'zmore',
        # 压缩工具
        'bunzip2', 'bzcat', 'bzip2', 'gunzip', 'gzip', 'lzma', 'uncompress', 'xz', 'xzcat',
        # 归档工具
        'cpio', 'tar',
        # 查找工具
        'find', 'which', 'whereis', 'xargs',
        # 用户/组相关
        'groups', 'id', 'login', 'logname', 'su', 'users', 'who', 'whoami',
        # 进程相关
        'kill', 'nice', 'nohup', 'pidof', 'pkill', 'pgrep', 'ps', 'watch',
        # 系统工具
        'arch', 'dmesg', 'hostname', 'lsblk', 'mount', 'mountpoint', 'systemctl', 'umount',
        # 网络工具（最小化安装仅保留现代网络工具，不含旧版 net-tools）
        'ip', 'ping', 'ping6', 'ss',
        # 编辑器
        'ed', 'sed',
        # 其他常用命令
        'awk', 'getopt', 'env', 'printenv', 'printf', 'test', '[', 'timeout', 'yes', 'unminimize',
        # 兼容链接
        'busybox',
    ],

    '/boot': ['System.map-6.8.0-56-generic', 'System.map-6.8.0-57-generic', 'config-6.8.0-56-generic', 'config-6.8.0-57-generic', 'grub', 'initrd.img', 'initrd.img-6.8.0-57-generic', 'initrd.img.old', 'lost+found', 'vmlinuz', 'vmlinuz-6.8.0-57-generic', 'vmlinuz.old'],
    '/boot/lost+found': [],

    '/cdrom': [],

    # /dev（最小化服务器裁剪，去除桌面相关设备项）
    '/dev': ['autofs', 'block', 'bsg', 'btrfs-control', 'bus', 'char', 'console', 'core', 'cpu_dma_latency', 'disk', 'dm-0', 'fd', 'full', 'fuse', 'hugepages', 'hwrng', 'initctl', 'input', 'kmsg', 'log', 'loop-control', 'loop0', 'loop1', 'loop2', 'loop3', 'loop4', 'loop5', 'loop6', 'loop7', 'mapper', 'mem', 'mqueue', 'net', 'null', 'nvram', 'port', 'ptmx', 'pts', 'random', 'rfkill', 'rtc', 'rtc0', 'sda', 'sda1', 'sda2', 'sda3', 'sg0', 'shm', 'stderr', 'stdin', 'stdout', 'tty', 'tty0', 'tty1', 'tty2', 'tty3', 'tty4', 'tty5', 'tty6', 'ttyS0', 'ttyS1', 'ubuntu-vg', 'urandom', 'vcs', 'vcs1', 'vcsa', 'vcsa1', 'vhost-net', 'zero'],

    # /etc（最小化服务器裁剪，去除桌面相关包配置）
    '/etc': ['X11', 'adduser.conf', 'alternatives', 'apparmor', 'apparmor.d', 'apport', 'apt', 'bash.bashrc', 'bindresvport.blacklist', 'binfmt.d', 'ca-certificates', 'ca-certificates.conf', 'cloud', 'console-setup', 'cron.d', 'cron.daily', 'cron.hourly', 'cron.monthly', 'cron.weekly', 'cryptsetup-initramfs', 'crypttab', 'dbus-1', 'debconf.conf', 'debian_version', 'default', 'deluser.conf', 'depmod.d', 'dhcp', 'dpkg', 'e2scrub.conf', 'environment', 'ethertypes', 'fstab', 'fuse.conf', 'gai.conf', 'gnutls', 'groff', 'group', 'group-', 'grub.d', 'gshadow', 'gshadow-', 'gss', 'host.conf', 'hostname', 'hosts', 'hosts.allow', 'hosts.deny', 'init.d', 'initramfs-tools', 'inputrc', 'iscsi', 'issue', 'issue.net', 'kernel', 'ld.so.cache', 'ld.so.conf', 'ld.so.conf.d', 'legal', 'libaudit.conf', 'locale.conf', 'localtime', 'login.defs', 'logrotate.d', 'lsb-release', 'lvm', 'machine-id', 'magic', 'magic.mime', 'mdadm', 'mime.types', 'mke2fs.conf', 'modprobe.d', 'modules', 'modules-load.d', 'mtab', 'multipath', 'multipath.conf', 'netplan', 'network', 'networkd-dispatcher', 'networks', 'nsswitch.conf', 'opt', 'os-release', 'pam.conf', 'pam.d', 'passwd', 'passwd-', 'perl', 'polkit-1', 'pollinate', 'profile', 'profile.d', 'protocols', 'python3', 'python3.12', 'rc0.d', 'rc1.d', 'rc2.d', 'rc3.d', 'rc4.d', 'rc5.d', 'rc6.d', 'rcS.d', 'resolv.conf', 'rpc', 'rsyslog.d', 'security', 'services', 'shadow', 'shadow-', 'shells', 'skel', 'ssh', 'ssl', 'subgid', 'subgid-', 'subuid', 'subuid-', 'sudo.conf', 'sudoers', 'sudoers.d', 'sysctl.conf', 'sysctl.d', 'systemd', 'terminfo', 'timezone', 'tmpfiles.d', 'ucf.conf', 'udev', 'ufw', 'update-motd.d', 'updatedb.conf', 'vconsole.conf', 'vim', 'vtrgb', 'wgetrc', 'xattr.conf'],

    '/etc/ssh': ['sshd_config'],
    '/etc/apt': ['sources.list'],

    '/home': ['admin', 'backup', 'ubuntu'],
    '/home/admin': ['.bash_history', '.bashrc', '.profile', '.ssh', 'credentials.bak'],
    '/home/admin/.ssh': ['authorized_keys', 'known_hosts'],
    '/home/backup': ['.bash_history', '.bashrc', '.profile', '.ssh', 'README.txt'],
    '/home/backup/.ssh': ['authorized_keys', 'known_hosts'],
    '/home/ubuntu': ['.bash_history', '.bashrc', '.profile', '.ssh'],
    '/home/ubuntu/.ssh': ['authorized_keys', 'known_hosts'],

    # /lib（最小化服务器裁剪）
    '/lib': ['apparmor', 'apt', 'binfmt.d', 'cloud-init', 'compat-ld', 'console-setup', 'cryptsetup', 'dbus-1.0', 'dpkg', 'environment.d', 'firmware', 'gnupg', 'grub', 'init', 'initramfs-tools', 'kernel', 'klibc', 'linux', 'locale', 'lsb', 'modprobe.d', 'modules', 'multipath', 'netplan', 'networkd-dispatcher', 'openssh', 'os-release', 'pam.d', 'polkit-1', 'python3', 'python3.12', 'snapd', 'ssl', 'sysctl.d', 'systemd', 'sysusers.d', 'tmpfiles.d', 'udev', 'x86_64-linux-gnu'],

    '/lib32': [],
    '/lib64': ['ld-linux-x86-64.so.2'],
    '/libx32': [],

    '/media': [],
    '/mnt': [],
    '/opt': [],

    '/proc': [],  # 动态生成，目录展示由 _cmd_ls 处理

    '/run': ['agetty.reload', 'blkid', 'cloud-init', 'console-setup', 'credentials', 'cryptsetup', 'dbus', 'dmeventd-client', 'dmeventd-server', 'fsck', 'initctl', 'initramfs', 'lock', 'log', 'lvm', 'lxd-installer.socket', 'motd.dynamic', 'mount', 'multipath', 'multipathd.pid', 'sendsigs.omit.d', 'setrans', 'shm', 'snapd-snap.socket', 'snapd.socket', 'ssh-unix-local', 'sshd', 'sshd.pid', 'sudo', 'systemd', 'tmpfiles.d', 'udev', 'user'],

    # /sbin（最小化服务器裁剪）
    '/sbin': ['aa-remove-unknown', 'aa-status', 'aa-teardown', 'addgroup', 'adduser', 'agetty', 'apparmor_parser', 'apparmor_status', 'arptables', 'blkid', 'blockdev', 'capsh', 'cfdisk', 'chcpu', 'chgpasswd', 'chmem', 'chpasswd', 'chroot', 'cpgr', 'cppw', 'cron', 'debugfs', 'delgroup', 'deluser', 'depmod', 'dhclient', 'dmidecode', 'dmsetup', 'dosfsck', 'dpkg-preconfigure', 'dpkg-reconfigure', 'e2fsck', 'ethtool', 'fdisk', 'fsck', 'fsck.ext4', 'gdisk', 'getty', 'groupadd', 'groupdel', 'groupmod', 'grub-install', 'grub-mkconfig', 'halt', 'hdparm', 'hwclock', 'init', 'insmod', 'ip', 'ip6tables', 'iptables', 'isosize', 'killall5', 'ldconfig', 'logrotate', 'losetup', 'lsmod', 'mkfs', 'mkfs.ext4', 'mkswap', 'modinfo', 'modprobe', 'nologin', 'parted', 'partprobe', 'pivot_root', 'poweroff', 'reboot', 'resize2fs', 'rfkill', 'rmmod', 'rsyslogd', 'runlevel', 'service', 'sfdisk', 'shadowconfig', 'shutdown', 'sshd', 'start-stop-daemon', 'sulogin', 'swapoff', 'swapon', 'switch_root', 'sysctl', 'tc', 'telinit', 'tune2fs', 'udevadm', 'ufw', 'unix_chkpwd', 'update-grub', 'update-initramfs', 'update-locale', 'update-passwd', 'update-rc.d', 'useradd', 'userdel', 'usermod', 'uuidd', 'visudo', 'wipefs', 'zramctl'],

    '/snap': ['README'],

    '/srv': [],

    '/sys': ['block', 'bus', 'class', 'dev', 'devices', 'firmware', 'fs', 'hypervisor', 'kernel', 'module', 'power'],

    '/tmp': ['snap-private-tmp', 'systemd-private-f97a78aa5d18494da956642062189958-systemd-logind.service-7J3O66'],

    '/usr': ['bin', 'games', 'include', 'lib', 'lib32', 'lib64', 'libexec', 'libx32', 'local', 'sbin', 'share', 'src'],

    '/var': ['backups', 'cache', 'crash', 'lib', 'local', 'lock', 'log', 'mail', 'opt', 'run', 'snap', 'spool', 'tmp', 'www']
}

VIRTUAL_FILES = {
    '/etc/passwd': '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/home/backup:/bin/bash
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:996:996:System Message Bus:/nonexistent:/usr/sbin/nologin
systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin
usbmux:x:101:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:990:990:User for polkitd:/:/usr/sbin/nologin
sshd:x:103:65534::/run/sshd:/usr/sbin/nologin
admin:x:1001:1001:Application Administrator:/home/admin:/bin/bash
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
''',

    '/etc/group': '''root:x:0:
daemon:x:1:pollinate
bin:x:2:
sys:x:3:
adm:x:4:syslog,ubuntu,admin
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:ubuntu
floppy:x:25:
tape:x:26:
sudo:x:27:ubuntu
audio:x:29:
dip:x:30:ubuntu
www-data:x:33:admin
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:ubuntu
staff:x:50:
games:x:60:
users:x:100:
kvm:x:108:
render:x:109:
netdev:x:114:
nogroup:x:65534:
systemd-network:x:998:
systemd-timesync:x:997:
messagebus:x:996:
systemd-resolve:x:991:
polkitd:x:990:
admin:x:1001:
ubuntu:x:1000:
sshd:x:65534:
''',

    '/etc/shadow': '''root:$y$j9T$ZRI.CJCLk7l11.y3CyP1P1$dMt5spgG5UdO1FRuZeinQXl5sfDXWVzV7/y106yaaY7:20483:0:99999:7:::
daemon:*:20193:0:99999:7:::
bin:*:20193:0:99999:7:::
sys:*:20193:0:99999:7:::
sync:*:20193:0:99999:7:::
games:*:20193:0:99999:7:::
man:*:20193:0:99999:7:::
lp:*:20193:0:99999:7:::
mail:*:20193:0:99999:7:::
news:*:20193:0:99999:7:::
uucp:*:20193:0:99999:7:::
proxy:*:20193:0:99999:7:::
www-data:*:20193:0:99999:7:::
backup:*:20193:0:99999:7:::
list:*:20193:0:99999:7:::
irc:*:20193:0:99999:7:::
_apt:*:20193:0:99999:7:::
nobody:*:20193:0:99999:7:::
systemd-network:!*:20193:::::1:
systemd-timesync:!*:20193:::::1:
dhcpcd:!:20193::::::
messagebus:!*:20193::::::
systemd-resolve:!*:20193:::::1:
usbmux:!:20193::::::
pollinate:!:20193::::::
polkitd:!*:20193::::::
sshd:!:20483::::::
admin:!:20483:0:99999:7:::
ubuntu:$6$yp1I6otJXKglnpgT$OTXzvnQOjn1o6f/ZxadUGjBzF8zFaKNoJqpDE.raQNhetVkKuQnXHTS.QJbv1KQEvlG8Mq3kuQ.WzspURCPso.:20483:0:99999:7:::
''',

    '/etc/gshadow': '''root:*::
adm:*::syslog,ubuntu,admin
sudo:*::ubuntu
www-data:*::admin
backup:!::
admin:!::
ubuntu:!::
sshd:!::
''',

    '/etc/gshadow-': '''root:*::
adm:*::syslog,ubuntu,admin
sudo:*::ubuntu
www-data:*::admin
backup:!::
admin:!::
ubuntu:!::
sshd:!::
''',

    '/etc/hosts': '''127.0.0.1   localhost
127.0.1.1   ubuntu-server
10.0.12.10   ubuntu-server
10.0.12.50    db-server
10.0.12.51    backup-server
10.0.12.1       vpn-gateway''',

    '/root/secret.txt': '''=== 内部服务器密码备忘 ===
SSH Backup: backup@10.0.12.51 / Backup#2024!
VPN: admin / vpn_secret_key
内网跳板: 10.0.12.50 (root / JumpServer@123)
API密钥: sk-xxxxxxxxxxxxxxxx
''',

    '/home/admin/credentials.bak': '''SSH Backup: backup@10.0.12.51 / Backup#2024!
内网跳板: 10.0.12.50 / JumpServer@123
VPN Gateway: 10.0.12.1 / admin:vpn2024''',

    '/home/admin/.bashrc': '''# ~/.bashrc
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
''',

    '/home/admin/.profile': '''# ~/.profile
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
''',

    '/home/admin/.bash_history': '''cd /var/www
ls -lah
tail -n 50 /var/log/syslog
grep -n "PasswordAuthentication" /etc/ssh/sshd_config
''',

    '/home/admin/.ssh/authorized_keys': '',

    '/home/admin/.ssh/known_hosts': '''10.0.12.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3s6xM7A9K4YwF7pM5h1v3uS9O9m5J2c5bJ8QfL2p7u
10.0.12.51 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5zvY7tZ9M2cX0hQ2uJ4bN1w8rT6kL0mP4qN7vS1d4g
''',

    '/home/ubuntu/.bashrc': '''# ~/.bashrc
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
''',

    '/home/ubuntu/.profile': '''# ~/.profile
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
''',

    '/home/ubuntu/.bash_history': '''sudo apt update
sudo systemctl status ssh
tail -f /var/log/auth.log
''',

    '/home/backup/.bashrc': '''# ~/.bashrc
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
alias ll='ls -alF'
alias la='ls -A'
''',

    '/home/backup/.profile': '''# ~/.profile
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
''',

    '/home/backup/.bash_history': '''cd /var/backups
ls -lah
tar -tf daily-web-2026-01-14.tar.gz | head
''',

    '/home/backup/README.txt': '''Nightly backup operator home.
Use this account for inventory checks and archive verification only.
''',

    '/root/.bashrc': '''# ~/.bashrc
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
alias ll='ls -la'
alias rm='rm -i'
PS1='\\u@\\h:\\w\\$ '
''',

    '/root/.bash_history': '''ls -la
cat /etc/passwd
ps -ef
ss -tulpn
history
cd /home/admin
cat credentials.bak
''',

    '/etc/hostname': 'ubuntu-server',

    '/etc/resolv.conf': '''# Generated by systemd-resolved
nameserver 127.0.0.53
options edns0 trust-ad
search localdomain''',

    '/etc/ssh/sshd_config': '''# OpenSSH server configuration
Port 22
AddressFamily any
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*''',

    '/root/.ssh/id_rsa': '''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0x5gV+Zi8r7K5HNpqHmDZy9X7vF1xE2h8kYE0fRVpBj1WmRjGxFi
K8NdG8L7jCdXH5U2fE+r3p5QAAAAwBk9XNza3lkZXZAZ21haWwuY29tAQIDAwED
-----END OPENSSH PRIVATE KEY-----''',

    '/root/.ssh/id_rsa.pub': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTHmBX5mLyvsrkc2moeYNnL1fu8XXETaHyRgTR9FWkGPVaZGMbEWIrw10bwvuMJ1cf root@ubuntu-server',

    '/root/.ssh/authorized_keys': '''ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTHmBX5mLyvsrkc2moeYNnL1fu8XXETaHyRgTR9FWkGPVaZGMbEWIrw10bwvuMJ1cf root@deploy-node-01''',

    '/var/log/auth.log': '''Jan 15 10:30:22 ubuntu-server sshd[512]: Server listening on 0.0.0.0 port 22.
Jan 15 10:30:22 ubuntu-server sshd[512]: Server listening on :: port 22.
Jan 20 14:22:15 ubuntu-server sshd[1024]: Accepted password for root from 10.0.12.50 port 52341 ssh2
Jan 20 14:22:15 ubuntu-server sshd[1024]: pam_unix(sshd:session): session opened for user root by (uid=0)
Jan 20 14:45:30 ubuntu-server sshd[1024]: pam_unix(sshd:session): session closed for user root
Jan 22 09:15:42 ubuntu-server sshd[1156]: Failed password for invalid user test from 203.0.113.50 port 44231 ssh2
Jan 22 09:15:44 ubuntu-server sshd[1156]: Failed password for invalid user guest from 203.0.113.50 port 44232 ssh2
''',

    # /etc/os-release 仅保留一个定义

    # 所有版本信息统一为 Ubuntu 24.04.2 LTS Noble Numbat
    '/etc/lsb-release': '''DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=24.04
DISTRIB_CODENAME=noble
DISTRIB_DESCRIPTION="Ubuntu 24.04.2 LTS"''',

    '/etc/issue': 'Ubuntu 24.04.2 LTS \\n \\l\n\n',
    '/etc/issue.net': 'Ubuntu 24.04.2 LTS',

    '/etc/os-release': '''PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble''',

    '/etc/apt/sources.list': '''# Ubuntu sources list
deb http://archive.ubuntu.com/ubuntu/ noble main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ noble-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ noble-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse''',
}

# 全局持久化文件系统（模拟真实被污染的环境）
GLOBAL_FS_STATE = copy.deepcopy(VIRTUAL_FS)
GLOBAL_FILES_CONTENT = copy.deepcopy(VIRTUAL_FILES)

