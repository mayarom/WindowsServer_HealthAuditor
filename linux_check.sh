#!/bin/bash

# יצירת קובץ טקסט בשולחן העבודה
output_file="$HOME/Desktop/SEND_TO_MAYA.txt"

echo "Collecting server information..." > $output_file

# גרסת מערכת ההפעלה
echo -e "\n=== Operating System Version ===" >> $output_file
lsb_release -a >> $output_file 2>&1
uname -r >> $output_file 2>&1

# מידע על עדכונים
echo -e "\n=== System Updates ===" >> $output_file
echo -e "\nLast Update Date:" >> $output_file
sudo grep "upgrade" /var/log/dpkg.log | tail -n 1 >> $output_file
echo -e "\nList of Installed Updates:" >> $output_file
sudo apt list --installed >> $output_file 2>&1

# מדיניות סיסמאות
echo -e "\n=== Password Policies ===" >> $output_file
grep -E '^password\s+requisite\s+pam_pwquality\.so' /etc/pam.d/common-password >> $output_file 2>&1
echo -e "\nPASS_MAX_DAYS (Maximum password age):" >> $output_file
grep '^PASS_MAX_DAYS' /etc/login.defs >> $output_file 2>&1
echo -e "\nPASS_MIN_DAYS (Minimum password age):" >> $output_file
grep '^PASS_MIN_DAYS' /etc/login.defs >> $output_file 2>&1
echo -e "\nPASS_WARN_AGE (Password expiration warning period):" >> $output_file
grep '^PASS_WARN_AGE' /etc/login.defs >> $output_file 2>&1
echo -e "\nPassword Complexity Requirements:" >> $output_file
grep '^password' /etc/pam.d/common-password >> $output_file 2>&1

# קבוצות משתמשים ומשתמשים
echo -e "\n=== User Groups and Users ===" >> $output_file
getent group | grep -E 'sudo|admin|wheel' >> $output_file 2>&1
echo -e "\n=== Admin Users ===" >> $output_file
getent passwd | awk -F: '$3 == 0 { print $1 }' >> $output_file 2>&1
grep -E '^sudo|^admin|^wheel' /etc/group | cut -d: -f4 >> $output_file 2>&1
echo -e "\n=== All User Groups and Members ===" >> $output_file
getent group >> $output_file 2>&1

# הגדרות ניהול השרת
echo -e "\n=== Server Management Settings ===" >> $output_file
echo -e "\nSSH Configuration:" >> $output_file
grep -E '^PermitRootLogin|^PasswordAuthentication' /etc/ssh/sshd_config >> $output_file 2>&1
echo -e "\nUFW Status:" >> $output_file
sudo ufw status >> $output_file 2>&1

# הגדרות ניטור
echo -e "\n=== Monitoring Settings ===" >> $output_file
echo -e "\nFail2Ban Status:" >> $output_file
sudo systemctl status fail2ban >> $output_file 2>&1
echo -e "\nCron Jobs:" >> $output_file
sudo crontab -l >> $output_file 2>&1
echo -e "\nSyslog Configuration:" >> $output_file
grep -E '^*.*' /etc/rsyslog.conf >> $output_file 2>&1

# תוכנות מותקנות
echo -e "\n=== Installed Software ===" >> $output_file
dpkg-query -l >> $output_file 2>&1

# סיום
echo "Information collection completed. Check the file at $output_file"
