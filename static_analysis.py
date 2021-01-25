import os

os.system('rm -rf ./pkgs')
print('Downloading Python packages in requirements.txt')
os.system('pip download -r requirements.txt -d ./pkgs --no-binary :all: > /dev/null 2>&1')
print('Collected the following files for static analysis\033[93m')
os.system("find pkgs \( -name '*.tar.gz' -o -name '*.zip' \) -type f -printf '%f\n'")
print('\033[0mExtracting source code')
os.system("find pkgs -name '*.tar.gz' -execdir tar -xzvf '{}' \; > /dev/null 2>&1")
os.system("find pkgs -name '*.zip' -execdir unzip -ou '{}' \; > /dev/null 2>&1")
print('Static Analysis')
os.system('pip install semgrep > /dev/null 2>&1')
os.system('semgrep -f static_scan_rules.yml pkgs/')
