#!/bin/bash


green='\e[32m'
blue='\e[34m'
clear='\e[0m'
yellow='\e[33m'
red='\e[31m'


ColorGreen(){
	echo -ne $green$1$clear
}

ColorYellow(){
	echo -ne $yellow$1$clear
}

ColorBlue(){
	echo -ne $blue$1$clear
}

ColorRed(){
    echo -ne $red$1$clear
}


function operative_system(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Operative System') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	source /etc/os-release
	echo "Name          :  ${NAME}"
	echo "Version       :  ${VERSION}"
	echo "Distributor ID:  ${VERSION_ID}"
	echo "Discription   :  ${PRETTY_NAME}"
	echo ""
	echo ""
}

function my_user_info(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'My User Info') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo "whoami        :  $(whoami)"
	echo "hostname      :  $(hostname)"
	echo ""
	echo ""
}

function sudo_version(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Sudo Version') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo $(sudo --version | grep "Sudo version")
	echo ""
	echo ""
}

function date_and_uptime(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Date And Uptime') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo $(uptime)
	echo ""
	echo ""
}

function system_stats(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'System Stats') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	stats=$(df -h --output=source,size,used,avail,pcent,target && echo "" && free -h)
	echo -e "$stats"
	echo ""
	echo ""
}

function cpu_info(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'CPU Info') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	info=$(cat /proc/cpuinfo)
	echo -e "$info"
	echo ""
	echo ""
}

function enviroment(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'ENVIROMENTS') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo "$(env)"
	echo ""
	echo ""
}

function get_signature_verification_failed(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get Signature Verification Failed') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	info=$(dmesg | grep -i "signature verification failed" 2>&1 || echo $(ColorRed 'Not Found'))
	echo -e "$info"
	echo ""
	echo ""
}

function get_disks(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get Disks') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo "$(lsblk -o NAME,MOUNTPOINT 2>&1 || $(ColorRed 'Not Found')))"
	echo ""
	echo ""
}

function available_software(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Available Software') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo " ========== $(ColorYellow 'Usefull') =========="
	echo ""
	usfull_list=$(for app in $(ls /usr/bin | grep -E '^[a-zA-Z0-9]+$'); do echo "/usr/bin/$app"; done)
	echo -e "$usfull_list"
	echo ""
	echo " ========== $(ColorYellow 'Installed Compiler') =========="
	echo ""
	echo -e "$(ls /usr/bin | grep -E 'gcc|g\+\+|clang|cc')"
	echo ""
	echo ""
}

function get_processes(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get Process') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	info=$(systemctl list-units --type=service --all && systemctl list-units --type=timer --all && systemctl list-units --type=socket --all && systemctl list-units --type=process --all && crontab -l)
	echo -e "$info"
	echo ""
	echo ""
}

function get_cronjobs(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get Cronjobs') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(ls -ltrh /etc/crontab)"
	echo -e "$(ls -ltrh /etc/cron.d)"
	echo -e "$(ls -ltrh /etc/cron.daily)"
	echo -e "$(ls -ltrh /etc/cron.hourly)"
	echo -e "$(ls -ltrh /etc/cron.monthly)"
	echo -e "$(ls -ltrh /etc/cron.weekly)"
	echo ""
	echo ""
}

function services(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Services') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(service --status-all)"
	echo ""
	echo ""
}

function system_timers(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'System Timers') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(systemctl list-timers --all)"
	echo ""
	echo ""
}

function sockets(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Sockets') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(systemctl list-sockets --all)"
	echo ""
	echo ""
}

function dbus_config_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'DBUS Config Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(ls -ltrh /etc/dbus-1)"
	echo -e "$(ls -ltrh /usr/share/dbus-a)"
	echo ""
	echo ""
}

function get_hosts(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'NETWORK') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo ""
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'Get Hosts') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(cat /etc/hosts)"
	echo ""
	echo ""
}

function interfaces(){
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'Interfaces') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(ip a)"
	echo ""
	echo ""
}

function open_ports(){
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'Open Ports') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(ss -lnt)"
	echo ""
	echo ""
}

function ip_routing(){
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'Ip Routing') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(ip route)"
	echo ""
	echo ""
}

function my_users(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Users') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo ""
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'My Users') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(cat /etc/passwd)"
	echo ""
	echo ""
}

function check_pgp_key(){
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'Check PGP Key') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(ls -ltrh /usr/bin/gpg)"
	echo ""
	echo ""
}

function check_sudo_tokens(){
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'Check Sudo Tokens') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(ls -ltrh /proc/sys/kernel/yama/ptrace_scope)"
	echo ""
	echo ""
}

function get_root_users(){
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'Get Root Users') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(grep ':0:' /etc/passwd)"
	echo ""
	echo ""
}

function get_console_users(){
	echo "$(ColorBlue 'IIIIIIIIIIIII ') $(ColorGreen 'Get Console Users') $(ColorBlue ' IIIIIIIIIIIII')"
	echo -e "$(grep -E '(/bin/bash|/bin/zsh|/bin/sh)' /etc/passwd)"
	echo ""
	echo ""
}

function mysql_info(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'MYSQL Info') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(mysql -V 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function psql_info(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'PSQL Info') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(psql --version 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function apache_info(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Apache Info') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(httpd -v 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function nginx_info(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Nginx Info') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(nginx -v 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function pass_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Pass Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(grep -ril 'pass' /etc 2>/dev/null | grep . || echo $(ColorRed 'Not Found /etc'))"
	echo ""
	echo -e "$(grep -ril 'pass' /home 2>/dev/null | grep . || echo $(ColorRed 'Not Found /home'))"
	echo ""
	echo ""
}

function get_web_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get Web Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(ls -ltrh /var/www)"
	echo -e "$(ls -ltrh /var/www/html)"
	echo ""
	echo ""
}

function get_all_hidden_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Hidden Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find /etc -type f -name '.*' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_all_openvpn_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All OpenVPN Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '*.ovpn' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_all_certificate_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Certificate Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '*.pem' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_cloud_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Cloud Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'cloud.conf' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_all_keyrings(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Keyrings') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'keyrings' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_all_passwd_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All passwd Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'passwd' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_all_github_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Github Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '.github' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .github'))"
	echo ""
	echo -e "$(find / -type f -name '.gitconfig' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .gitconfig'))"
	echo ""
	echo -e "$(find / -type f -name '.git-credentials' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .git-credentials'))"
	echo ""
	echo -e "$(find / -type f -name '.git' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .git'))"
	echo ""
	echo ""
}

function get_all_pgp_gpg_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All PGP-GPG Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '*.pgp' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .pgp'))"
	echo ""
	echo -e "$(find / -type f -name '*.gpg' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .gpg'))"
	echo ""
	echo -e "$(find / -type f -name '*.gnupg' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .gnupg'))"
	echo ""
	echo ""
}

function get_all_swp_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All SWP Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '*.swp' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_google_chrome(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get Google Chrome') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'google-chrome' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_auto_login_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get Auto Login Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'autologin.conf' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_snmp_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Snap Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'snmpd.conf' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_pypirc_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All pypirc Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '.pypirc' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	
}

function get_ldaprc_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Ldaprc Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '.ldaprc' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_env_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All env Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '.env' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_msmtprc_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Msmtprc Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '.msmtprc' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_keepass_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Keepass Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '*.kdbx' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .kdbx'))"
	echo ""
	echo -e "$(find / -type f -name 'KeePass.config*' 2>/dev/null | grep . || echo $(ColorRed 'Not Found KeePass.config'))"
	echo ""
	echo -e "$(find / -type f -name 'KeePass.ini' 2>/dev/null | grep . || echo $(ColorRed 'Not Found KeePass.ini'))"
	echo ""
	echo -e "$(find / -type f -name 'KeePass.enforced*' 2>/dev/null | grep . || echo $(ColorRed 'Not Found KeePass.enforced'))"
	echo ""
	echo ""
}

function get_ftp_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All FTP Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '*.ftpconfig' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .ftpconfig'))"
	echo ""
	echo -e "$(find / -type f -name 'ffftp.ini' 2>/dev/null | grep . || echo $(ColorRed 'Not Found ffftp.ini'))"
	echo ""
	echo -e "$(find / -type f -name 'ftp.ini' 2>/dev/null | grep . || echo $(ColorRed 'Not Found ftp.ini'))"
	echo ""
	echo -e "$(find / -type f -name 'ftp.config' 2>/dev/null | grep . || echo $(ColorRed 'Not Found ftp.config'))"
	echo ""
	echo -e "$(find / -type f -name 'sites.ini' 2>/dev/null | grep . || echo $(ColorRed 'Not Found sites.ini'))"
	echo ""
	echo -e "$(find / -type f -name 'wcx_ftp.ini' 2>/dev/null | grep . || echo $(ColorRed 'Not Found wcx_ftp.ini'))"
	echo ""
	echo -e "$(find / -type f -name 'winscp.ini' 2>/dev/null | grep . || echo $(ColorRed 'Not Found winscp.ini'))"
	echo ""
	echo -e "$(find / -type f -name 'ws_ftp.ini' 2>/dev/null | grep . || echo $(ColorRed 'Not Found ws_ftp.ini'))"
	echo ""
	echo ""
}

function get_bind_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Bind Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'bind' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_seed_dms_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Seed DMS Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'seeddms*' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_ddclient_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All DDClient Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'ddclient.config' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_cacti_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All CACTI Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'cacti' 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_log_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All LOG Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name 'access.log' 2>/dev/null | grep . || echo $(ColorRed 'Not Found access.log'))"
	echo ""
	echo -e "$(find / -type f -name 'error.log' 2>/dev/null | grep . || echo $(ColorRed 'Not Found error.log'))"
	echo ""
	echo ""
}

function get_intetesting_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All Intetesting Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -type f -name '.bashrc' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .bashrc'))"
	echo ""
	echo -e "$(find / -type f -name '.google_authenticator' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .google_authenticator'))"
	echo ""
	echo -e "$(find / -type f -name 'hosts.equiv' 2>/dev/null | grep . || echo $(ColorRed 'Not Found hosts.equiv'))"
	echo ""
	echo -e "$(find / -type f -name '.plan' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .plan'))"
	echo ""
	echo -e "$(find / -type f -name '.profile' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .profile'))"
	echo ""
	echo -e "$(find / -type f -name '.recently-used.xbel' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .recently-used.xbel'))"
	echo ""
	echo -e "$(find / -type f -name '.rhosts' 2>/dev/null | grep . || echo $(ColorRed 'Not Found .rhosts'))"
	echo ""
	echo -e "$(find / -type f -name 'sudo_as_admin_successful' 2>/dev/null | grep . || echo $(ColorRed 'Not Found sudo_as_admin_successful'))"
	echo ""
	echo ""
}

function sgid_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All SGID Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -perm -2000 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_cap_files(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get All CAP Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(getcap -r / 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_writable_dirs(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get Writable Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -writable -type d 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}

function get_suid_app_path(){
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'II')"
	echo "$(ColorBlue 'IIIIIIIIIIIIIIIIIIIIIII ') $(ColorGreen 'Get SUID APP Files') $(ColorBlue ' IIIIIIIIIIIIIIIIIIIIIII')"
	echo -e "$(find / -perm -u=s -type f 2>/dev/null | grep . || echo $(ColorRed 'Not Found'))"
	echo ""
	echo ""
}


function all_checks(){
	operative_system
	my_user_info
	sudo_version
	date_and_uptime
	enviroment
	system_stats
	cpu_info
	get_signature_verification_failed
	get_disks
	available_software
	get_processes
	get_cronjobs
	services
	system_timers
	sockets
	dbus_config_files
	get_hosts
	interfaces
	open_ports
	ip_routing
	my_users
	check_pgp_key
	check_sudo_tokens
	get_root_users
	get_console_users
	mysql_info
	psql_info
	apache_info
	nginx_info
	pass_files
	get_web_files
	get_all_hidden_files
	get_all_openvpn_files
	get_all_certificate_files
	get_cloud_files
	get_all_keyrings
	get_all_passwd_files
	get_all_github_files
	get_all_pgp_gpg_files
	get_all_swp_files
	get_google_chrome
	get_auto_login_files
	get_snmp_files
	get_pypirc_files
	get_ldaprc_files
	get_env_files
	get_msmtprc_files
	get_keepass_files
	get_ftp_files
	get_bind_files
	get_seed_dms_files
	get_ddclient_files
	get_cacti_files
	get_log_files
	get_intetesting_files
	sgid_files
	get_cap_files
	get_writable_dirs
	get_suid_app_path
}

all_checks
