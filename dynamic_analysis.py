import re
import subprocess
from pathlib import Path


EXEC = re.compile(r', \[.*\]')
IP = re.compile(r'inet_addr\(\".+\"\)')
PORT = re.compile(r'htons\([0-9]+\)')
KNOWN_CONNECT = {
    '127.0.0.53:53', # DNS Lookup
    '151.101.0.223:443', # PyPI
    '151.101.128.223:443', # PyPI
    '151.101.64.223:443', # PyPI
    '151.101.188.223:443', # PyPI
    '151.101.192.223:443', # PyPI
    '151.101.0.223:443', # PyPI
    '151.101.189.63:443', # PyPI
    '151.101.197.63:443', # PyPI
    '192.30.255.113:9418', # Github
    '192.30.255.112:9418', # Github
}
ENV_LOCATIONS = {
    '/etc/environment',
    '/etc/profile',
    '/etc/bashrc',
    '~/.bash_profile',
    '~/.bashrc',
    '~/.profile',
    '~/.cshrc',
    '~/.zshrc',
    '~/.tcshrc',
}
BAD_COMMANDS = {
    '"set"',
    '"env"',
}


def check_path(pkg, syscall):
    path = syscall.split('"')[1]
    for loc in ENV_LOCATIONS:
        if Path(loc).expanduser().as_posix() == path:
            print(f'\033[93m{pkg} tried to access sensitive environment location [{path}] during installation.\033[0m')
   

def check_cmd(pkg, syscall):
    args = EXEC.search(syscall)
    match_str = args.group()
    if any(cmd in match_str for cmd in BAD_COMMANDS):
        print(f'\033[91m{pkg} tried to access environment variable by executing {match_str} command during installation.\033[0m')


def check_connect(pkg, syscall):
    ipo = IP.search(syscall)
    porto = PORT.search(syscall)
    ip_addr = ipo.group().replace('inet_addr(', '').replace('"', '').replace(')', '')
    port = porto.group().replace('htons(', '').replace(')', '')
    loc = f'{ip_addr}:{port}'
    if loc in KNOWN_CONNECT:
        return
    print(f'\033[94m{pkg} tried to connect to [{loc}] during installation.\033[0m')


def lookup_env(pkg, syscalls):
    """Check syscalls for malicious activities."""
    calls = syscalls.splitlines()
    for i in calls:
        if 'openat(' in i:
            check_path(pkg, i)
        elif 'execve(' in i:
            check_cmd(pkg, i)
        elif 'connect(' in i and 'sin_addr=' in i:
            check_connect(pkg, i)


def collect_syscalls(pkg):
    print(f'Analyzing: {pkg}')
    """Collect sensitive system calls during installation."""
    args = [
        'strace', '-s', '2000', '-fqqe',
        'trace=openat,execve,connect','--seccomp-bpf',
        'pip', 'install', '--no-cache'] + pkg.split()
    return subprocess.check_output(args, stderr=subprocess.STDOUT).decode('utf-8', 'ignore')


def check_packages():
    pkgs = Path('./requirements.txt').read_text().splitlines()
    for pkg in pkgs:
        # Handle comments in requirements file.
        if pkg.startswith('#'):
            continue
        if '# ' in pkg:
            pkg = pkg.split('# ')[0]
        syscalls = collect_syscalls(pkg)
        if '#egg=' in pkg:
            pkg = pkg.split('#egg=')[1]
        lookup_env(pkg, syscalls)


if __name__ == "__main__":
    check_packages()