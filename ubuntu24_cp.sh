#!/bin/bash

echo "Ubuntu24 CyberPatriot Script"

LOG="cp_fix_log.txt"
echo "CyberPatriot Ubuntu Script Started $(date)" | tee "$LOG"

#Users and Passwords

echo "Listing All Users" | tee -a "$LOG"
awk -F: '$3 >= 1000 {print $1}' /etc/passwd | tee -a "$LOG"

echo "[+] Enforcing password policy" | tee -a "$LOG"
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 10/' /etc/login.defs

echo "[+] Ensuring empty passwords disabled" | tee -a "$LOG"
sed -i 's/nullok//g' /etc/pam.d/common-auth

#SSH Hardening

SSHD="/etc/ssh/sshd_config"
echo "[+] Hardening SSH" | tee -a "$LOG"

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' $SSHD
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' $SSHD
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' $SSHD
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' $SSHD
sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 30/' $SSHD

echo "[!] IMPORTANT: Add allowed users manually to sshd_config" | tee -a "$LOG"
echo "    Example: AllowUsers gooduser1 gooduser2" | tee -a "$LOG"

systemctl restart ssh

#Permission Fixes

echo "[+] Fixing sensitive file permissions" | tee -a "$LOG"

chmod 640 /etc/shadow
chown root:shadow /etc/shadow

chmod 644 /etc/passwd
chmod 600 /boot/grub/grub.cfg

echo "[+] Checking /etc/sudoers (manual check required)" | tee -a "$LOG"

#Firewall and Network hardening

echo "[+] Enabling firewall" | tee -a "$LOG"
ufw --force enable
ufw allow OpenSSH

echo "[+] Enabling TCP SYN cookies (DDoS mitigation)" | tee -a "$LOG"
sysctl -w net.ipv4.tcp_syncookies=1

#Auto updates

echo "[+] Enabling automatic updates" | tee -a "$LOG"
cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

#Services Daemons

echo "[+] Listing all services" | tee -a "$LOG"
systemctl list-units --type=service --all | tee -a "$LOG"

# Disable suspicious / unnecessary ones manually:
# systemctl stop SERVICE
# systemctl disable SERVICE
# systemctl mask SERVICE

#RM illegal and dangerous software

BAD_PKGS=(
    nmap
    hydra
    john
    netcat
    nikto
    wireshark
)

echo "[+] Removing known dangerous packages" | tee -a "$LOG"
for pkg in "${BAD_PKGS[@]}"; do
    if dpkg -l | grep -q "^ii\s*$pkg"; then
        apt remove --purge -y "$pkg"
        echo "Removed: $pkg" | tee -a "$LOG"
    fi
done

#Malware and Backdoor scans

echo "[+] Scanning for suspicious files" | tee -a "$LOG"

find / -type f -name "*.mp3" 2>/dev/null | tee -a "$LOG"
find / -type f -name "*.torrent" 2>/dev/null | tee -a "$LOG"
find / -type f -name "*.sh" 2>/dev/null | tee -a "$LOG"
find / -type f -name "*.py" 2>/dev/null | tee -a "$LOG"

echo "[+] Checking cron jobs" | tee -a "$LOG"
crontab -l | tee -a "$LOG"
sudo crontab -l -u root | tee -a "$LOG"
ls -al /etc/cron.daily | tee -a "$LOG"
ls -al /etc/cron.hourly | tee -a "$LOG"
ls -al /etc/cron.weekly | tee -a "$LOG"

#System Updates

echo "[+] Updating package lists and installed programs" | tee -a "$LOG"
apt update -y
apt upgrade -y