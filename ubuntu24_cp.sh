#!/bin/bash

echo "=== CyberPatriot Ubuntu 24 Script Started ==="
LOG="cp_fix_log.txt"
echo "Script started at $(date)" | tee "$LOG"

#______________________________________________
# 1. LIST USERS
#----------------------------------------------
echo "[+] Listing normal users (UID ≥ 1000)" | tee -a "$LOG"
awk -F: '$3 >= 1000 {print $1}' /etc/passwd | tee -a "$LOG"

#______________________________________________
# 2. PASSWORD POLICY
#----------------------------------------------
echo "[+] Enforcing strong password policy" | tee -a "$LOG"

sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs

sed -i 's/nullok//g' /etc/pam.d/common-auth

#______________________________________________
# 3. SSH HARDENING
#----------------------------------------------
SSHD="/etc/ssh/sshd_config"

echo "[+] Securing SSH (non-destructive)" | tee -a "$LOG"

sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' $SSHD
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' $SSHD
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' $SSHD
sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 30/' $SSHD

# Do NOT disable password authentication unless README tells you.
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' $SSHD

echo "[!] IMPORTANT: Manually add allowed users to sshd_config!" | tee -a "$LOG"
echo "Example: AllowUsers gooduser1 gooduser2" | tee -a "$LOG"

systemctl restart ssh 2>/dev/null

#______________________________________________
# 4. FILE PERMISSIONS
#----------------------------------------------
echo "[+] Fixing sensitive file permissions" | tee -a "$LOG"

chmod 640 /etc/shadow
chown root:shadow /etc/shadow

chmod 644 /etc/passwd
chmod 600 /boot/grub/grub.cfg 2>/dev/null

#______________________________________________
# 5. FIREWALL DETECTION
#----------------------------------------------
echo "[+] Checking firewall availability" | tee -a "$LOG"

if command -v ufw >/dev/null 2>&1; then
    echo "[+] UFW found. Enabling..." | tee -a "$LOG"
    ufw --force enable
    ufw allow OpenSSH
else
    echo "[!] UFW not found. Installing UFW..." | tee -a "$LOG"
    apt install -y ufw
    ufw --force enable
    ufw allow OpenSSH
fi

#______________________________________________
# 6. NETWORK HARDENING
#----------------------------------------------
echo "[+] Enabling TCP SYN cookies (DDoS protection)" | tee -a "$LOG"
sysctl -w net.ipv4.tcp_syncookies=1
#______________________________________________
# 7. AUTOMATIC SECURITY UPDATES
#----------------------------------------------
echo "[+] Enabling automatic updates" | tee -a "$LOG"

cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
#______________________________________________
# 8. REMOVE SUSPICIOUS / ILLEGAL PACKAGES
#----------------------------------------------
BAD_PKGS=(
    nmap
    hydra
    john
    netcat
    nikto
    wireshark
    aircrack-ng
    ettercap
)

echo "[+] Removing dangerous software" | tee -a "$LOG"
for pkg in "${BAD_PKGS[@]}"; do
    if dpkg -s "$pkg" 2>/dev/null | grep -q "install ok"; then
        apt remove --purge -y "$pkg"
        echo "Removed: $pkg" | tee -a "$LOG"
    fi
done

#______________________________________________
# 9. SUSPICIOUS FILE SCAN (HOME ONLY)
#______________________________________________
echo "[+] Scanning user directories for illegal files" | tee -a "$LOG"

find /home -type f \( -name "*.mp3" -o -name "*.torrent" -o -name "*.exe" \) 2>/dev/null | tee -a "$LOG"

#______________________________________________
# 10. CRON AUDIT
#______________________________________________
echo "[+] Checking cron jobs" | tee -a "$LOG"

crontab -l | tee -a "$LOG"
sudo crontab -l -u root | tee -a "$LOG"

ls -al /etc/cron.daily | tee -a "$LOG"
ls -al /etc/cron.hourly | tee -a "$LOG"
ls -al /etc/cron.weekly | tee -a "$LOG"

#______________________________________________
# 11. SERVICES AUDIT
#______________________________________________
echo "[+] Listing all services (manual disable REQUIRED)" | tee -a "$LOG"
systemctl list-units --type=service --all | tee -a "$LOG"

echo "[!] IMPORTANT: Disable suspicious services manually:" | tee -a "$LOG"
echo "    systemctl disable SERVICE" | tee -a "$LOG"
echo "    systemctl stop SERVICE"    | tee -a "$LOG"

#______________________________________________
# 12. UPDATE SYSTEM
#______________________________________________
echo "[+] Updating system packages" | tee -a "$LOG"
apt update -y
apt upgrade -y

echo "=== Script Completed $(date) ===" | tee -a "$LOG"
