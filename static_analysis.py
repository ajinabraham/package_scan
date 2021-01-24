import os

os.system('rm -rf ./pkgs')
print('Downloading Python packages in requirements.txt')
os.system('pip download -r requirements.txt -d ./pkgs --no-binary :all: > /dev/null 2>&1')
print('Extracting source code')
os.system("find pkgs -name '*.tar.gz' -execdir tar -xzvf '{}' \; > /dev/null 2>&1")
os.system("find pkgs -name '*.zip' -execdir unzip -ou '{}' \; > /dev/null 2>&1")
print('Static Analysis')
os.system('pip install semgrep > /dev/null 2>&1')
os.system('semgrep -f static_scan_rules.yml pkgs/')