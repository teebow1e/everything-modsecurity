#!/bin/bash

green='\e[32m'
reset='\e[0m'
y='\e[33m'
red='\e[31m'

if [[ $EUID -ne 0 ]]; then
   	echo -e "${red}[!] This script must be run as root${reset}";
   	exit 1
else
  echo -e "${y}[+] Found root privilege${reset}";
fi

echo -e "${green}[*] Installing NGINX from apt..${reset}";
sudo apt update -y
if sudo apt install -y nginx; then
  echo -e "${green}[*] Checking NGINX version..${reset}"
  echo -e "${green}[+] Found NGINX version: $(nginx -v 2>&1)${reset}"
else
  echo -e "${red}[!] Failed to install NGINX${reset}"
  exit 1
fi
echo

echo -e "${green}[*] Installing ModSecurity Module v3..${reset}";
echo -e "${green}[*] Getting NGINX Connector for ModSecurity Module..${reset}"
if git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /usr/local/src/ModSecurity/ && sudo apt -y install libmodsecurity3; then
  echo -e "${green}[+] ModSecurity v3 installed successfully${reset}"
else
  echo -e "${red}[!] Failed to install ModSecurity${reset}"
  exit 1
fi

echo -e "${green}[*] Getting NGINX Connector for ModSecurity Module..${reset}";
# compiled connector for nginx (compiled version have to match)
nginx_version=$(nginx -v 2>&1 | grep -Po '\d+\.\d+')
ubuntu_release=$(lsb_release -a 2>&1 | grep 'Release:.*' | sed 's/Release://' | awk '{$1=$1};1')
mkdir -p /etc/nginx/modules
cp ./modsecurity-connector/${ubuntu_release}_${nginx_version}/ngx_http_modsecurity_module.so  /etc/nginx/modules/ngx_http_modsecurity_module.so

echo -e "${green}[*] Creating backup version of /etc/nginx/nginx.conf ...${reset}";
cp /etc/nginx/nginx.conf /etc/nginx/nginx.default.bak
echo -e "${green}[*] Enabling ModSecurity in nginx.conf ...${reset}";
sed -i '1i\load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;' /etc/nginx/nginx.conf
sed -i '/http {/a \    modsecurity on;\n    modsecurity_rules_file /etc/nginx/modsec/modsec-config.conf;' /etc/nginx/nginx.conf

echo -e "${green}[*] Preparing configuration for NGINX + ModSecurity..${reset}";
sudo mkdir /var/log/modsec/
sudo chmod 777 /var/log/modsec/
sudo mkdir /etc/nginx/modsec/
sudo cp /usr/local/src/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecAuditLogParts ABIJDEFHZ/SecAuditLogParts ABCEFHJKZ/' /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecAuditEngine RelevantOnly/SecAuditEngine On/' /etc/nginx/modsec/modsecurity.conf
sed -i 's/SecAuditLogType Serial/#SecAuditLogType Serial/' /etc/nginx/modsec/modsecurity.conf
sed -i 's#^SecAuditLog /var/log/modsec_audit.log#SecAuditLogType Serial\nSecAuditLog /var/log/modsec/modsec_audit.json\nSecAuditLogFormat JSON\nSecAuditLogStorageDir /var/log/modsec/\nSecAuditLogFileMode 0777\nSecAuditLogDirMode 0777#' /etc/nginx/modsec/modsecurity.conf
sed -i 's#^SecResponseBodyMimeType text/plain text/html text/xml#SecResponseBodyMimeType text/plain text/html text/xml application/json#' /etc/nginx/modsec/modsecurity.conf

# Create modsec-config.conf File
echo "Include /etc/nginx/modsec/modsecurity.conf" > /etc/nginx/modsec/modsec-config.conf
sudo cp /usr/local/src/ModSecurity/unicode.mapping /etc/nginx/modsec/
rm -rf /usr/local/src/ModSecurity

echo -e "${green}[*] Installing OWASP Core Rule Set for ModSecurity..${reset}";
cd /etc/nginx/modsec
wget https://github.com/coreruleset/coreruleset/archive/refs/tags/nightly.tar.gz
tar -xvf nightly.tar.gz
sudo cp /etc/nginx/modsec/coreruleset-nightly/crs-setup.conf.example /etc/nginx/modsec/coreruleset-nightly/crs-setup.conf
echo "Include /etc/nginx/modsec/coreruleset-nightly/crs-setup.conf" >> /etc/nginx/modsec/modsec-config.conf
echo "Include /etc/nginx/modsec/coreruleset-nightly/rules/*.conf" >> /etc/nginx/modsec/modsec-config.conf
rm -rf nightly.tar.gz

echo -e "${green}[*] Creating ModSecurity custom rules template: /etc/nginx/modsec/custom-rules/*${reset}";
mkdir /etc/nginx/modsec/custom-rules
touch /etc/nginx/modsec/custom-rules/default.conf
echo "Include /etc/nginx/modsec/custom-rules/*.conf" >> /etc/nginx/modsec/modsec-config.conf


echo -e "${green}[*] Removing some rules because of Modsec/OWASP_CRS version compatibility${reset}";
# Ubuntu 22.04 LTS - libmodsecurity3.0.6-1
# Ubuntu 20.04 LTS - libmodsecurity3.0.4-1build1
if [ "$ubuntu_release" = "20.04" ]; then
  sed -i -E 's/^SecArgumentsLimit /# SecArgumentsLimit /'  /etc/nginx/modsec/modsecurity.conf # > 3.0.5 required
  sed -i -E 's/^SecRequestBodyJsonDepthLimit /# SecRequestBodyJsonDepthLimit /'  /etc/nginx/modsec/modsecurity.conf # > 3.0.6 required
fi
rm /etc/nginx/modsec/coreruleset-nightly/rules/REQUEST-922-MULTIPART-ATTACK.conf # > 2.9.6 or 3.0.8 required: https://forum.directadmin.com/threads/owasp-modsecurity-core-rule-set-version-3-3-4.67101/

echo -e "${green}[*] Creating ModSecurity backup version of /etc/nginx/nginx.conf ...${reset}";
cp /etc/nginx/nginx.conf /etc/nginx/nginx.modsec.bak

echo -e "${green}[+] Checking availability...${reset}";
nginx -t
service nginx restart

read -p "$(echo -e "${green}Do you want to test the ModSecurity WAF now? (y/n): ${reset}")" test_option

if [[ $test_option == "y" || $test_option == "Y" ]]; then
  xss_test=$(curl -s 'http://localhost/?a=whoami;')
  echo "$xss_test"
  if [[ $xss_test == *"403 Forbidden"* ]] && [ "${#xss_test}" != '0' ]; then
    echo -e "${y}[403 Forbidden]: Malicious requests blocked.${reset}"
    echo -e "${green}[+] Installation completed. Enjoy!${reset}"
  else
    echo -e "${red}Something probably gone wrong, please check journalctl of NGINX!${reset}"
  fi
else
  echo -e "${green}[+] Please run the following command to test ModSecurity rules:${reset}"
  echo -e "curl 'http://localhost:80/?a=whoami;'"; $reset
fi
