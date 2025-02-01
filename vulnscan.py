#!/usr/bin/env python3
import os
import subprocess
import re
import platform
import sys
import json
import hashlib
import argparse
from datetime import datetime
from collections import defaultdict
import colorama
from colorama import Fore, Style

colorama.init()

class LinuxSecurityScanner:
    def __init__(self):
        self.results = defaultdict(list)
        self.severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        self.is_root = os.geteuid() == 0
        
        # Use platform.freedesktop_os_release() for distro info
        distro_info = platform.freedesktop_os_release() 
        self.distro = distro_info['NAME'].lower()  
        
        self.file_hashes = {}
        self.sensitive_files = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/etc/crontab'
        ]

    def print_finding(self, severity, title, description, remediation=''):
        color = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.MAGENTA,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.CYAN
        }.get(severity, Fore.WHITE)
        
        self.severity_counts[severity] += 1
        output = [
            f"\n{color}▐ {severity.ljust(8)} {Style.RESET_ALL} {title}",
            f"{Fore.WHITE}Description: {Style.RESET_ALL}{description}"
        ]
        
        if remediation:
            output.append(f"{Fore.GREEN}Remediation: {Style.RESET_ALL}{remediation}")
        
        print('\n'.join(output))

    def check_privileges(self):
        if not self.is_root:
            self.print_finding('HIGH', 'Insufficient Privileges', 
                            'Running without root privileges - many checks will be limited',
                            'Run the scanner with sudo')
            return False
        return True

    def check_system_updates(self):
        try:
            if self.distro in ['ubuntu', 'debian']:
                result = subprocess.run(['apt-get', '-s', 'upgrade'], capture_output=True, text=True)
                updates = re.findall(r'(\d+) upgraded', result.stdout)
                if updates and int(updates) > 0:
                    self.print_finding('HIGH', 'Pending System Updates',
                                     f"{updates} packages need updating",
                                     "Run 'apt-get update && apt-get upgrade'")
            elif self.distro in ['centos', 'redhat']:
                result = subprocess.run(['yum', 'check-update'], capture_output=True, text=True)
                if result.returncode == 100:
                    self.print_finding('HIGH', 'Pending System Updates',
                                     "Packages need updating",
                                     "Run 'yum update'")
        except Exception as e:
            self.print_finding('MEDIUM', 'Update Check Failed', str(e))

    def check_cve_vulnerabilities(self):
        try:
            if self.distro in ['ubuntu', 'debian']:
                result = subprocess.run(['apt-get', 'upgrade', '-s'], capture_output=True, text=True)
                if 'security updates' in result.stdout:
                    self.print_finding('CRITICAL', 'Potential CVEs Found',
                                      "System may be vulnerable to known CVEs",
                                      "Review output of 'apt-get upgrade -s' and run 'apt-get upgrade'")
            # Add RHEL/CentOS CVE check logic here (e.g., using 'yum updateinfo list security all')
        except Exception as e:
            self.print_finding('MEDIUM', 'CVE Check Failed', str(e))

    def check_file_integrity(self):
        try:
            for file in self.sensitive_files:
                if os.path.exists(file):
                    with open(file, 'rb') as f:
                        self.file_hashes[file] = hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            self.print_finding('MEDIUM', 'File Integrity Check Failed', str(e))

    def check_ssh_config(self):
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                ssh_config = f.read()
            
            checks = [
                ('PermitRootLogin yes', 'HIGH', 'SSH Root Login Enabled'),
                ('PasswordAuthentication yes', 'MEDIUM', 'SSH Password Authentication Enabled'),
                ('Protocol 1', 'CRITICAL', 'Using Insecure SSH Protocol v1')
            ]
            
            for pattern, severity, title in checks:
                if re.search(pattern, ssh_config):
                    self.print_finding(severity, title,
                                     f"Insecure SSH configuration: {pattern}",
                                     f"Disable {pattern.split()} in /etc/ssh/sshd_config")
        except Exception as e:
            self.print_finding('MEDIUM', 'SSH Config Check Failed', str(e))

    def check_firewall_status(self):
        try:
            if self.distro in ['ubuntu', 'debian']:
                ufw = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                if 'Status: inactive' in ufw.stdout:
                    self.print_finding('HIGH', 'Firewall Disabled',
                                      'Uncomplicated Firewall (UFW) is not active',
                                      'Enable and configure UFW')
            # Add iptables/centos checks here (e.g., using 'firewall-cmd --state')
        except Exception as e:
            self.print_finding('MEDIUM', 'Firewall Check Failed', str(e))

    def check_suid_files(self):
        try:
            result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f'], 
                                  capture_output=True, text=True)
            suid_files = result.stdout.splitlines()
            if len(suid_files) > 50:  # Baseline threshold
                self.print_finding('MEDIUM', 'Excessive SUID Files',
                                 f"Found {len(suid_files)} SUID files",
                                 "Review SUID files with 'find / -perm -4000'")
        except Exception as e:
            self.print_finding('MEDIUM', 'SUID Check Failed', str(e))

    def check_malware(self):
        try:
            if not subprocess.run(['which', 'clamscan'], stdout=subprocess.DEVNULL).returncode == 0:
                self.print_finding('MEDIUM', 'Malware Scanner Not Found',
                                 'ClamAV not installed', 'Install ClamAV')
            else:
                result = subprocess.run(['freshclam'], capture_output=True, text=True)
                if 'out of date' in result.stdout:
                    self.print_finding('MEDIUM', 'Outdated Malware Signatures',
                                     'ClamAV signatures need updating',
                                     'Run freshclam manually')
        except Exception as e:
            self.print_finding('MEDIUM', 'Malware Check Failed', str(e))

    def generate_report(self):
        report = {
            'timestamp': datetime.now().isoformat(),
            'system': {
                'distribution': platform.freedesktop_os_release(), # Use freedesktop_os_release() here as well
                'kernel': platform.uname().release,
                'architecture': platform.machine()
            },
            'findings': self.results,
            'summary': self.severity_counts
        }
        with open('security_scan.json', 'w') as f:
            json.dump(report, f, indent=2)

    def run_scan(self):
        print(f"\n{Fore.BLUE}=== DeepSeek Linux Security Scanner ==={Style.RESET_ALL}")
        
        if self.check_privileges():
            self.check_file_integrity()
            self.check_system_updates()
            self.check_cve_vulnerabilities()
            self.check_ssh_config()
            self.check_firewall_status()
            self.check_suid_files()
            self.check_malware()
        
        self.generate_report()
        
        print(f"\n{Fore.BLUE}=== Scan Summary ==={Style.RESET_ALL}")
        for severity, count in self.severity_counts.items():
            print(f"{severity.ljust(8)}: {count}")
        print(f"\n{Fore.YELLOW}Report saved to security_scan.json{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Advanced Linux Security Scanner')
    parser.add_argument('--scan-level', type=str, default='normal',
                      choices=['quick', 'normal', 'full'],
                      help='Scan intensity level')
    args = parser.parse_args()
    
    scanner = LinuxSecurityScanner()
    scanner.run_scan()