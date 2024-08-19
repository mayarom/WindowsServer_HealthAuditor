#!/bin/bash

# Create a text file on the Desktop
output_file="$HOME/Desktop/SEND_TO_MAYA.txt"

echo "===============================" > $output_file
echo "  Server Information Report  " >> $output_file
echo "===============================" >> $output_file
echo "Date: $(date)" >> $output_file
echo "Hostname: $(hostname)" >> $output_file
echo -e "\n" >> $output_file

# Operating System Version
echo "=== Operating System Version ===" >> $output_file
lsb_release -a >> $output_file 2>&1
uname -r >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# System Updates Information
echo "=== System Updates ===" >> $output_file
echo "Last Update Date:" >> $output_file
sudo grep "upgrade" /var/log/dpkg.log | tail -n 1 >> $output_file
echo -e "\nList of Installed Updates:" >> $output_file
sudo apt list --installed >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Password Policies
echo "=== Password Policies ===" >> $output_file
grep -E '^password\s+requisite\s+pam_pwquality\.so' /etc/pam.d/common-password >> $output_file 2>&1
echo -e "\nPASS_MAX_DAYS (Maximum password age):" >> $output_file
grep '^PASS_MAX_DAYS' /etc/login.defs >> $output_file 2>&1
echo -e "\nPASS_MIN_DAYS (Minimum password age):" >> $output_file
grep '^PASS_MIN_DAYS' /etc/login.defs >> $output_file 2>&1
echo -e "\nPASS_WARN_AGE (Password expiration warning period):" >> $output_file
grep '^PASS_WARN_AGE' /etc/login.defs >> $output_file 2>&1
echo -e "\nPassword Complexity Requirements:" >> $output_file
grep '^password' /etc/pam.d/common-password >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# User Groups and Users
echo "=== User Groups and Users ===" >> $output_file
getent group | grep -E 'sudo|admin|wheel' >> $output_file 2>&1
echo -e "\nAdmin Users:" >> $output_file
getent passwd | awk -F: '$3 == 0 { print $1 }' >> $output_file 2>&1
grep -E '^sudo|^admin|^wheel' /etc/group | cut -d: -f4 >> $output_file 2>&1
echo -e "\nAll User Groups and Members:" >> $output_file
getent group >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Server Management Settings
echo "=== Server Management Settings ===" >> $output_file
echo -e "\nSSH Configuration:" >> $output_file
grep -E '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config >> $output_file 2>&1
echo -e "\nUFW Status:" >> $output_file
sudo ufw status >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Monitoring Settings
echo "=== Monitoring Settings ===" >> $output_file
echo -e "\nFail2Ban Status:" >> $output_file
sudo systemctl status fail2ban >> $output_file 2>&1
echo -e "\nCron Jobs:" >> $output_file
sudo crontab -l >> $output_file 2>&1
echo -e "\nSyslog Configuration:" >> $output_file
grep -E '^*.*' /etc/rsyslog.conf >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Installed Software
echo "=== Installed Software ===" >> $output_file
dpkg-query -l >> $output_file 2>&1
echo -e "\n-------------------------------\n" >> $output_file

# Additional Security Checks
echo "=== Additional Security Checks ===" >> $output_file

# Check active services
echo -e "\nActive Services:" >> $output_file
systemctl list-units --type=service --state=running >> $output_file 2>&1

# Check active network connections
echo -e "\nActive Network Connections:" >> $output_file
netstat -tuln >> $output_file 2>&1

# Check sudoers configuration
echo -e "\nSudoers Configuration:" >> $output_file
sudo cat /etc/sudoers | grep -v '^#' >> $output_file 2>&1

# Check for vulnerable packages
echo -e "\nVulnerable Packages Check:" >> $output_file
sudo apt-get -s upgrade | grep "^Inst" | grep -i securi >> $output_file 2>&1

echo -e "\n-------------------------------\n" >> $output_file

# Completion message
echo "Information collection completed. Check the file at $output_file"
