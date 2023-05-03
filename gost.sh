#! /bin/bash
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[etelaat]${Font_color_suffix}"
Error="${Red_font_prefix}[eshtebah]${Font_color_suffix}"
shell_version="1.1.1"
ct_new_ver="2.11.2" # 2.x donbal nakardan berozresani
gost_conf_path="/etc/gost/config.json"
raw_conf_path="/etc/gost/rawconf"

function checknew() {
  # استفاده از دستور gost --version برای دریافت نسخه
  checknew=$(gost --version 2>&1 | awk '{print $2}')
  
  # چاپ پیام
  echo "Behtarin noskhe: $checknew"
  read -p "Berozresani? (y/n): " checknewnum
  
  # اجرای دستورات بروزرسانی
  if [[ $checknewnum == [yY] ]]; then
    # ایجاد یک نسخه پشتیبان از تنظیمات gost
    cp -r /etc/gost /tmp/
    
    # اجرای فانکشن ارتقا
    Install_ct
    
    # حذف نسخه قدیمی و جابجایی نسخه جدید
    rm -rf /etc/gost
    mv /tmp/gost /etc/
    
    # راه‌اندازی مجدد سرویس gost
    systemctl restart gost
  else
    exit 0
  fi
}


function check_sys() {
  # چک کردن توزیع لینوکسی
  if [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif grep -q -E -i "debian" /etc/issue; then
    release="debian"
  elif grep -q -E -i "ubuntu" /etc/issue; then
    release="ubuntu"
  elif grep -q -E -i "centos|red hat|redhat" /etc/issue; then
    release="centos"
  elif grep -q -E -i "debian" /proc/version; then
    release="debian"
  elif grep -q -E -i "ubuntu" /proc/version; then
    release="ubuntu"
  elif grep -q -E -i "centos|red hat|redhat" /proc/version; then
    release="centos"
  fi
  
  # چک کردن معماری CPU
  bit=$(uname -m)
  if [[ "$bit" != "x86_64" ]]; then
    read -p "Tarashe CPU khod ra entekhab konid: " bit
  else
    bit="amd64"
  fi
}



function Installation_dependency() {
  # اجرای دستور gzip -V و بررسی وجود آن
  if ! gzip -V >/dev/null 2>&1; then
    # در صورت نبود gzip، نصب وابستگی‌ها
    if [[ ${release} == "centos" ]]; then
      yum update
      yum install -y gzip wget
    else
      apt-get update
      apt-get install -y gzip wget
    fi
  fi
}



function check_root() {
  if [[ $EUID != 0 ]]; then
    echo -e "${Error} Shoma ba hesab karbari hastid, baraye edame bayad az hesab root estefade konid ${Green_background_prefix}sudo su${Font_color_suffix}"
    exit 1
  fi
}

function check_new_ver() {
  # دریافت آخرین نسخه با استفاده از دستور curl
  ct_new_ver=$(curl --silent "https://api.github.com/repos/ginuerzh/gost/releases/latest" | grep -Po '"tag_name": "\K.*?(?=")')
  if [[ -z ${ct_new_ver} ]]; then
    ct_new_ver="2.11.2"
    echo -e "${Error} Akharin noskhe Avalin Bar Daryaft Neshod، Danlod az v${ct_new_ver}"
  else
    echo -e "${Info} Akharin noskhe Gost: ${ct_new_ver}"
  fi
}



function check_file() {
  if [[ ! -d "/usr/lib/systemd/system/" ]]; then
    mkdir -p /usr/lib/systemd/system/
    chmod 777 /usr/lib/systemd/system/
  fi
}

function check_nor_file() {
  rm -f "$(pwd)/gost" "$(pwd)/gost.service" "$(pwd)/config.json"
  rm -rf /etc/gost /usr/lib/systemd/system/gost.service /usr/bin/gost
}


function Install_ct() {
  check_root
  check_nor_file
  Installation_dependency
  check_file
  check_sys
  # check_new_ver
  read -e -p "Are you in China? It is recommended to use domestic mirrors for faster download speeds. [y/n]: " addyn
  [[ -z ${addyn} ]] && addyn="n"
  if [[ ${addyn} =~ [Yy] ]]; then
    curl -L -o gost-linux-amd64.gz https://github.com/ginuerzh/gost/releases/download/v2.11.5/gost-freebsd-amd64-2.11.5.gz
  else
    curl -L -o gost-linux-amd64.gz https://github.com/go-gost/gost/releases/download/v3.0.0-rc7/gost_3.0.0-rc7_linux_amd64.tar.gz
  fi
  gzip -d gost-linux-amd64.gz
  mv gost-linux-amd64 /usr/bin/gost
  chmod 777 /usr/bin/gost
  
  curl -L -o gost.service https://raw.githubusercontent.com/Cna-mrd/gost/master/gost.service
  chmod 644 gost.service
  mv gost.service /usr/lib/systemd/system/
  
  mkdir /etc/gost
  curl -L -o /etc/gost/config.json https://raw.githubusercontent.com/Cna-mrd/gost/master/config.json
  chmod 777 /etc/gost
  
  systemctl daemon-reload
  systemctl enable gost.service
  systemctl restart gost.service
  
  echo "------------------------------"
  if [[ -e /usr/bin/gost && -e /usr/lib/systemctl/gost.service && -e /etc/gost/config.json ]]; then
    echo "Gost has been installed successfully."
    rm -rf "$(pwd)/gost" "$(pwd)/gost.service" "$(pwd)/config.json"
  else
    echo "Gost installation failed."
    rm -rf "$(pwd)/gost" "$(pwd)/gost.service" "$(pwd)/config.json" "$(pwd)/gost.sh"
  fi
}





function Uninstall_ct() {
  systemctl stop gost.service
  systemctl disable gost.service
  rm -rf /usr/bin/gost /usr/lib/systemd/system/gost.service /etc/gost "$(pwd)/gost.sh"
  echo "Gost has been uninstalled."
}
function Start_ct() {
  systemctl start gost.service
  echo "Gost has been started."
}
function Stop_ct() {
  systemctl stop gost.service
  echo "Gost has been stopped."
}
function Restart_ct() {
  systemctl restart gost.service
  echo "Please check the log to verify whether the restart was successful."
}



function read_protocol() {
  cat <<EOF
Choose a protocol:
-----------------------------------
[1] Non-encrypted TCP+UDP traffic forwarding
     Use for internal traffic forwarding
-----------------------------------
[2] Encrypted TCP+UDP traffic forwarding
     Use for forwarding traffic originally encrypted at lower levels, such as HTTPS
     Choose this protocol if you want to receive and decrypt encrypted traffic, then forward to another node or service
-----------------------------------
[3] Decrypt the traffic transmitted by gost and forward it
     Use for traffic encrypted by gost. Decrypt and forward to a local proxy service port or forward to a remote node.
     Generally used to receive transit traffic from a foreign machine.
-----------------------------------
[4] One-click installation of a ss/socks5/http proxy
     Uses Gost's built-in proxy protocol. Lightweight and easy to manage.
-----------------------------------
[5] Load balancing with multiple endpoints
     Supports various encryption methods.
-----------------------------------
[6] Forwarding to self-selected CDN nodes
     Set up in transit only.
-----------------------------------
EOF
  read -p "Please enter the protocol number: " numprotocol

  case "$numprotocol" in
    1)
      flag_a="nonencrypt"
      ;;
    2)
      encrypt
      ;;
    3)
      decrypt
      ;;
    4)
      proxy
      ;;
    5)
      enpeer
      ;;
    6)
      cdn
      ;;
    *)
      echo "Invalid input. Please try again."
      exit 1
      ;;
  esac
}



function read_s_port() {
  case "$flag_a" in
    ss|socks|http)
      echo "-----------------------------------"
      read -p "Please enter the password for $flag_a: " flag_b
      ;;
    *)
      echo "------------------------------------------------------------------"
      read -p "Please enter the port to receive forwarded traffic: " flag_b
      ;;
   esac
}



function read_d_ip() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "May I ask the ss encryption you want to set(Only a few commonly used): "
    echo -e "-----------------------------------"
    echo -e "[1] aes-256-gcm"
    echo -e "[2] aes-256-cfb"
    echo -e "[3] chacha20-ietf-poly1305"
    echo -e "[4] chacha20"
    echo -e "[5] rc4-md5"
    echo -e "[6] AEAD_CHACHA20_POLY1305"
    echo -e "-----------------------------------"
    read -p "Please choose ss encryption method: " ssencrypt
    if [ "$ssencrypt" == "1" ]; then
      flag_c="aes-256-gcm"
    elif [ "$ssencrypt" == "2" ]; then
      flag_c="aes-256-cfb"
    elif [ "$ssencrypt" == "3" ]; then
      flag_c="chacha20-ietf-poly1305"
    elif [ "$ssencrypt" == "4" ]; then
      flag_c="chacha20"
    elif [ "$ssencrypt" == "5" ]; then
      flag_c="rc4-md5"
    elif [ "$ssencrypt" == "6" ]; then
      flag_c="AEAD_CHACHA20_POLY1305"
    else
      echo "type error, please try again"
      exit
    fi
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -p "Please enter the socks username: " flag_c
  elif [ "$flag_a" == "http" ]; then
    echo -e "-----------------------------------"
    read -p "Please enter http username: " flag_c
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Please enter the landing list file name"
    read -e -p "Custom but different configurations should not be repeated，no suffix，For example ips1、iplist2: " flag_c
    touch $flag_c.txt
    echo -e "------------------------------------------------------------------"
    echo -e "Please enter the landing ip and port you want to balance the load in turn"
    while true; do
      echo -e "Would you like to switch this unit from${flag_b}The IP or domain name to which the received traffic is forwarded?"
      read -p "vared konid: " peer_ip
      echo -e "Would you like to switch this unit from${flag_b}Received traffic is forwarded to${peer_ip}Which port of?"
      read -p "vared konid: " peer_port
      echo -e "$peer_ip:$peer_port" >>$flag_c.txt
      read -e -p "Whether to continue to add landing？[Y/n]:" addyn
      [[ -z ${addyn} ]] && addyn="y"
      if [[ ${addyn} == [Nn] ]]; then
        echo -e "------------------------------------------------------------------"
        echo -e "$flag_c.txt has been created in the root directory, you can edit this file"
		echo -e " at any time to modify the landing information, restart gost to take effect"
        echo -e "------------------------------------------------------------------"
        break
      else
        echo -e "------------------------------------------------------------------"
        echo -e "Continue to add balanced load landing configuration"
      fi
    done
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "Change the unit from${flag_b}The self-selected ip to which the received traffic is forwarded:"
    read -p "please enter: " flag_c
    echo -e "Would you like to switch this unit from${flag_b}Received traffic is forwarded to${flag_c}Which port of?"
    echo -e "[1] 80"
    echo -e "[2] 443"
    echo -e "[3]Custom port (such as 8080, etc.)"
    read -p "Please select a port: " cdnport
    if [ "$cdnport" == "1" ]; then
      flag_c="$flag_c:80"
    elif [ "$cdnport" == "2" ]; then
      flag_c="$flag_c:443"
    elif [ "$cdnport" == "3" ]; then
      read -p "Please enter a custom port: " customport
      flag_c="$flag_c:$customport"
    else
      echo "type error, please try again"
      exit
    fi
  else
    echo -e "------------------------------------------------------------------"
    echo -e "May I ask which IP or domain name you want to forward the traffic received by this machine from ${flag_b}?"
    echo -e "Note: The IP can be either the public network IP of [remote machine/current machine], or the local loopback IP of this machine (ie 127.0.0.1)"
    echo -e "Filling in the specific IP address depends on the IP that the service receiving the traffic is listening to (see: /Cna-mrd/gost)"
    if [[ ${is_cert} == [Yy] ]]; then
      echo -e "Note: The landing machine opens a custom tls certificate, be sure to fill in ${Red_font_prefix} domain name ${Font_color_suffix}"
    fi
    read -p "please enter: " flag_c
  fi
}



function read_d_port() {
  case "$flaga" in 
    "ss")
      printf "%s\n" "------------------------------------------------------------------" \
        "May I ask which port you want to set for the SS proxy service?"
      read -p "Please enter: " flagd
      ;;
    "socks")
      printf "%s\n" "------------------------------------------------------------------" \
        "May I ask which port you want to set for the SOCKS proxy service?"
      read -p "Please enter: " flagd
      ;;
    "http")
      printf "%s\n" "------------------------------------------------------------------" \
        "May I ask which port you want to set for the HTTP proxy service?"
      read -p "Please enter: " flagd
      ;;
    "peer")
      printf "%s\n" "------------------------------------------------------------------" \
        "Balancing load strategy: " \
        "-----------------------------------" \
        "[1] round - Round-robin" \
        "[2] random - Random" \
        "[3] fifo - First in, first out" \
        "-----------------------------------"
      read -p "Please select a load balancing type: " num_stra
      case "$num_stra" in
        "1")
          flag_d="round"
          ;;
        "2")
          flag_d="random"
          ;;
        "3")
          flag_d="fifo"
          ;;
        )
          echo "Type error, please try again"
          exit
          ;;
      esac
      ;;
    "cdn")
      printf "%s\n" "------------------------------------------------------------------" \
        "Please enter the host:"
      read -p "Please enter: " flag_d
      ;;
    )
      printf "%s\n" "------------------------------------------------------------------" \
        "May I ask which port you want to forward the traffic received by this machine from ${flagb} to ${flagc}?"
      read -p "Please enter: " flagd
      if [[ ${iscert} == Yy ]]; then
        flagd="$flagd?secure=true"
      fi
      ;;
  esac
}



function eachconf_retrieve() {
  d_server=${trans_conf#*#}
  d_port=${d_server#*#}
  d_ip=${d_server%%:*}
  flag_s_port=${trans_conf%%#*}
  is_encrypt=${flag_s_port%/*}
  s_port=${flag_s_port##*/}
}

function confstart() {
  printf "%s\n" "{
    \"Debug\": true,
    \"Retries\": 0," > "$gost_conf_path"
  if [ "$multiconf" = true ]; then
    echo -e "    \"ServeNodes\": [" >> "$gost_conf_path"
  else
    echo -e "    \"ServeNodes\": [" >> "$gost_conf_path"
  fi
}

function rawconf() {
  printf "%s\n\n" "+-----------------------------------+"
  printf "%s\n" "| GOST Transport Layer Configuration |"
  printf "%s\n\n" "+-----------------------------------+"
  
  read_protocol
  read_s_port
  read_d_ip
  read_d_port
  conf_json="{
    \"protocol\": \"$flag_a\",
    \"local_ip\": \"$flag_b\",
    \"remote_ip\": \"$flag_c\",
    \"remote_port\": \"$flag_d\",
    \"encrypt\": \"$ssencrypt\",
    \"username\": \"$flag_c\",
    \"list_file\": \"$flag_c.txt\",
    \"balance\": \"$flag_d\",
    \"cdn_host\": \"$flag_d\"
  }"
  echo "$conf_json" >> "$gost_conf_path"
}
function confend() {
  echo -e "\n    ]
}" >> "$gost_conf_path"
}





function conflast() {
  echo "    ]
}" >>$gost_conf_path
}
function multiconflast() {
  if [ $i -eq $count_line ]; then
    echo "            ]
        }" >>$gost_conf_path
  else
    echo "            ]
        }," >>$gost_conf_path
  fi
}




function encrypt() {
  printf "%s\n" "请问您要设置的转发传输类型: "
  printf "%s\n" "-----------------------------------"
  printf "%s\n" "[1] tls隧道"
  printf "%s\n" "[2] ws隧道"
  printf "%s\n" "[3] wss隧道"
  printf "%s\n" "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认开启tcp+udp"
  printf "%s\n" "-----------------------------------"
  read -p "请选择转发传输类型: " numencrypt

  if [ "$numencrypt" == "1" ]; then
    flag_a="encrypttls"
  elif [ "$numencrypt" == "2" ]; then
    flag_a="encryptws"
  elif [ "$numencrypt" == "3" ]; then
    flag_a="encryptwss"
  else
    printf "%s\n" "type error, please try again"
    exit
  fi
}




function enpeer() {
  echo -e "请问您要设置的均衡负载传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密转发"
  echo -e "[2] tls隧道"
  echo -e "[3] ws隧道"
  echo -e "[4] wss隧道"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认同一配置的传输类型相同"
  echo -e "此脚本仅支持简单型均衡负载，具体可参考官方文档"
  echo -e "gost均衡负载官方文档：/gost/load-balancing"
  echo -e "-----------------------------------"
  read -p "请选择转发传输类型: " numpeer

  if [ "$numpeer" == "1" ]; then
    flag_a="peerno"
  elif [ "$numpeer" == "2" ]; then
    flag_a="peertls"
  elif [ "$numpeer" == "3" ]; then
    flag_a="peerws"
  elif [ "$numpeer" == "4" ]; then
    flag_a="peerwss"

  else
    echo "type error, please try again"
    exit
  fi
}




function cdn() {
  echo -e "请问您要设置的CDN传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密转发"
  echo -e "[2] ws隧道"
  echo -e "[3] wss隧道"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！"
  echo -e "此功能只需在中转机设置"
  echo -e "-----------------------------------"
  read -p "请选择CDN转发传输类型: " numcdn

  if [ "$numcdn" == "1" ]; then
    flag_a="cdnno"
  elif [ "$numcdn" == "2" ]; then
    flag_a="cdnws"
  elif [ "$numcdn" == "3" ]; then
    flag_a="cdnwss"
  else
    echo "type error, please try again"
    exit
  fi
}
function cert() {
  echo -e "-----------------------------------"
  echo -e "[1] ACME一键申请证书"
  echo -e "[2] 手动上传证书"
  echo -e "-----------------------------------"
  echo -e "说明: 仅用于落地机配置，默认使用的gost内置的证书可能带来安全问题，使用自定义证书提高安全性"
  echo -e "     配置后对本机所有tls/wss解密生效，无需再次设置"
  read -p "请选择证书生成方式: " numcert

  if [ "$numcert" == "1" ]; then
    check_sys
    if [[ ${release} == "centos" ]]; then
      yum install -y socat
    else
      apt-get install -y socat
    fi
    read -p "请输入ZeroSSL的账户邮箱(至 zerossl.com 注册即可)：" zeromail
    read -p "请输入解析到本机的域名：" domain
    curl https://get.acme.sh | sh
    "$HOME"/.acme.sh/acme.sh --set-default-ca --server zerossl
    "$HOME"/.acme.sh/acme.sh --register-account -m "${zeromail}" --server zerossl
    echo -e "ACME证书申请程序安装成功"
    echo -e "-----------------------------------"
    echo -e "[1] HTTP申请（需要80端口未占用）"
    echo -e "[2] Cloudflare DNS API 申请（需要输入APIKEY）"
    echo -e "-----------------------------------"
    read -p "请选择证书申请方式: " certmethod
    if [ "certmethod" == "1" ]; then
      echo -e "请确认本机${Red_font_prefix}80${Font_color_suffix}端口未被占用, 否则会申请失败"
      if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "SSL 证书生成成功，默认申请高安全性的ECC证书"
        if [ ! -d "$HOME/gost_cert" ]; then
          mkdir $HOME/gost_cert
        fi
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath $HOME/gost_cert/cert.pem --keypath $HOME/gost_cert/key.pem --ecc --force; then
          echo -e "SSL 证书配置成功，且会自动续签，证书及秘钥位于用户目录下的 ${Red_font_prefix}gost_cert${Font_color_suffix} 目录"
          echo -e "证书目录名与证书文件名请勿更改; 删除 gost_cert 目录后用脚本重启,即自动启用gost内置证书"
          echo -e "-----------------------------------"
        fi
      else
        echo -e "SSL 证书生成失败"
        exit 1
      fi
    else
      read -p "请输入Cloudflare账户邮箱：" cfmail
      read -p "请输入Cloudflare Global API Key：" cfkey
      export CF_Key="${cfkey}"
      export CF_Email="${cfmail}"
      if "$HOME"/.acme.sh/acme.sh --issue --dns dns_cf -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "SSL 证书生成成功，默认申请高安全性的ECC证书"
        if [ ! -d "$HOME/gost_cert" ]; then
          mkdir $HOME/gost_cert
        fi
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath $HOME/gost_cert/cert.pem --keypath $HOME/gost_cert/key.pem --ecc --force; then
          echo -e "SSL 证书配置成功，且会自动续签，证书及秘钥位于用户目录下的 ${Red_font_prefix}gost_cert${Font_color_suffix} 目录"
          echo -e "证书目录名与证书文件名请勿更改; 删除 gost_cert 目录后使用脚本重启, 即重新启用gost内置证书"
          echo -e "-----------------------------------"
        fi
      else
        echo -e "SSL 证书生成失败"
        exit 1
      fi
    fi

  elif [ "$numcert" == "2" ]; then
    if [ ! -d "$HOME/gost_cert" ]; then
      mkdir $HOME/gost_cert
    fi
    echo -e "-----------------------------------"
    echo -e "已在用户目录建立 ${Red_font_prefix}gost_cert${Font_color_suffix} 目录，请将证书文件 cert.pem 与秘钥文件 key.pem 上传到该目录"
    echo -e "证书与秘钥文件名必须与上述一致，目录名也请勿更改"
    echo -e "上传成功后，用脚本重启gost会自动启用，无需再设置; 删除 gost_cert 目录后用脚本重启,即重新启用gost内置证书"
    echo -e "-----------------------------------"
  else
    echo "type error, please try again"
    exit
  fi
}
function decrypt() {
  echo -e "请问您要设置的解密传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] tls"
  echo -e "[2] ws"
  echo -e "[3] wss"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认开启tcp+udp"
  echo -e "-----------------------------------"
  read -p "请选择解密传输类型: " numdecrypt

  if [ "$numdecrypt" == "1" ]; then
    flag_a="decrypttls"
  elif [ "$numdecrypt" == "2" ]; then
    flag_a="decryptws"
  elif [ "$numdecrypt" == "3" ]; then
    flag_a="decryptwss"
  else
    echo "type error, please try again"
    exit
  fi
}
function proxy() {
  echo -e "------------------------------------------------------------------"
  echo -e "请问您要设置的代理类型: "
  echo -e "-----------------------------------"
  echo -e "[1] shadowsocks"
  echo -e "[2] socks5(强烈建议加隧道用于Telegram代理)"
  echo -e "[3] http"
  echo -e "-----------------------------------"
  read -p "请选择代理类型: " numproxy
  if [ "$numproxy" == "1" ]; then
    flag_a="ss"
  elif [ "$numproxy" == "2" ]; then
    flag_a="socks"
  elif [ "$numproxy" == "3" ]; then
    flag_a="http"
  else
    echo "type error, please try again"
    exit
  fi
}
function method() {
  if [ $i -eq 1 ]; then
    if [ "$is_encrypt" == "nonencrypt" ]; then
      echo "        \"tcp://:$s_port/$d_ip:$d_port\",
        \"udp://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnno" ]; then
      echo "        \"tcp://:$s_port/$d_ip?host=$d_port\",
        \"udp://:$s_port/$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerno" ]; then
      echo "        \"tcp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\",
        \"udp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encrypttls" ]; then
      echo "        \"tcp://:$s_port\",
        \"udp://:$s_port\"
    ],
    \"ChainNodes\": [
        \"relay+tls://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptwss" ]; then
      echo "        \"tcp://:$s_port\",
		  \"udp://:$s_port\"
	],
	\"ChainNodes\": [
		\"relay+wss://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peertls" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+tls://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerwss" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+wss://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnws" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+ws://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnwss" ]; then
      echo "        \"tcp://:$s_port\",
    	\"udp://:$s_port\"
	],
	\"ChainNodes\": [
    	\"relay+wss://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decrypttls" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        \"relay+tls://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        \"relay+tls://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "decryptws" ]; then
      echo "        \"relay+ws://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptwss" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        \"relay+wss://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        \"relay+wss://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "ss" ]; then
      echo "        \"ss://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "socks" ]; then
      echo "        \"socks5://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "http" ]; then
      echo "        \"http://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    else
      echo "config error"
    fi
  elif [ $i -gt 1 ]; then
    if [ "$is_encrypt" == "nonencrypt" ]; then
      echo "                \"tcp://:$s_port/$d_ip:$d_port\",
                \"udp://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerno" ]; then
      echo "                \"tcp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\",
                \"udp://:$s_port?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnno" ]; then
      echo "                \"tcp://:$s_port/$d_ip?host=$d_port\",
                \"udp://:$s_port/$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encrypttls" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+tls://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptws" ]; then
      echo "                \"tcp://:$s_port\",
	            \"udp://:$s_port\"
	        ],
	        \"ChainNodes\": [
	            \"relay+ws://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "encryptwss" ]; then
      echo "                \"tcp://:$s_port\",
		        \"udp://:$s_port\"
		    ],
		    \"ChainNodes\": [
		        \"relay+wss://$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peertls" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+tls://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerws" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+ws://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "peerwss" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+wss://:?ip=/root/$d_ip.txt&strategy=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnws" ]; then
      echo "                \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+ws://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "cdnwss" ]; then
      echo "                 \"tcp://:$s_port\",
                \"udp://:$s_port\"
            ],
            \"ChainNodes\": [
                \"relay+wss://$d_ip?host=$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decrypttls" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        		  \"relay+tls://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        		  \"relay+tls://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "decryptws" ]; then
      echo "        		  \"relay+ws://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "decryptwss" ]; then
      if [ -d "$HOME/gost_cert" ]; then
        echo "        		  \"relay+wss://:$s_port/$d_ip:$d_port?cert=/root/gost_cert/cert.pem&key=/root/gost_cert/key.pem\"" >>$gost_conf_path
      else
        echo "        		  \"relay+wss://:$s_port/$d_ip:$d_port\"" >>$gost_conf_path
      fi
    elif [ "$is_encrypt" == "ss" ]; then
      echo "        \"ss://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "socks" ]; then
      echo "        \"socks5://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    elif [ "$is_encrypt" == "http" ]; then
      echo "        \"http://$d_ip:$s_port@:$d_port\"" >>$gost_conf_path
    else
      echo "config error"
    fi
  else
    echo "config error"
    exit
  fi
}




function writeconf() {
  count_line=$(awk 'END{print NR}' $raw_conf_path)
  for ((i = 1; i <= $count_line; i++)); do
    if [ $i -eq 1 ]; then
      trans_conf=$(sed -n "${i}p" $raw_conf_path)
      eachconf_retrieve
      method
    elif [ $i -gt 1 ]; then
      if [ $i -eq 2 ]; then
        echo "    ],
    \"Routes\": [" >>$gost_conf_path
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        multiconfstart
        method
        multiconflast
      else
        trans_conf=$(sed -n "${i}p" $raw_conf_path)
        eachconf_retrieve
        multiconfstart
        method
        multiconflast
      fi
    fi
  done
}




function show_all_conf() {
  echo -e "                      GOST peykarbandi                        "
  echo -e "--------------------------------------------------------"
  echo -e "Number|Method\t|Local Port\t|Destination Address:Destination Port"
  echo -e "--------------------------------------------------------"

 if [ ! -s "$raw_conf_path" ]; then
  echo "Error: Configuration file is empty or does not exist"
  exit 1
fi

count_line=$(awk 'END{print NR}' "$raw_conf_path")

while read -r line
do
  is_encrypt=$(echo "$line" | awk -F "=" '{print $2}')
  case "$is_encrypt" in
    "nonencrypt")
      str="haml va naghle bedone ramznegari"
      ;;
    "encrypttls")
      str=" tls tonel "
      ;;
    "encryptws")
      str="  ws tonel "
      ;;
    "encryptwss")
      str=" wss tonel "
      ;;
    "peerno")
      str=" moteadel konande bare tonel bedone ramznegari "
      ;;
    "peertls")
      str=" tls taadole bare tonel "
      ;;
    "peerws")
      str="  ws taadole bare tonel "
      ;;
    "peerwss")
      str=" wss taadole bare tonel "
      ;;
    "decrypttls")
      str=" tls ramz goshai "
      ;;
    "decryptws")
      str="  ws ramz goshai "
      ;;
    "decryptwss")
      str=" wss ramz goshai "
      ;;
    "ss")
      str="   ss   "
      ;;
    "socks")
      str=" socks5 "
      ;;
    "http")
      str=" http "
      ;;
    "cdnno")
      str="ersale bedone ramznegari CDN"
      ;;
    "cdnws")
      str="ws ersale tonel CDN"
      ;;
    "cdnwss")
      str="wss ersale tonel CDN"
      ;;
    *)
      str=""
      ;;
  esac

  eachconf_retrieve "$str"
done < "$raw_conf_path"

    echo -e " $i  |$str  |$s_port\t|$d_ip:$d_port"
    echo -e "--------------------------------------------------------"
  
}

cron_restart() {
  echo -e "------------------------------------------------------------------"
  echo -e "kar rah andazi mojadad gost: "
  echo -e "-----------------------------------"
  echo -e "[1] tanzim gost baraye rah andazi mojadad"
  echo -e "[2] barname rizi mojadad gost ra hazf konid"
  echo -e "-----------------------------------"
  read -p "lotfan entekhab konid: " numcron
  if [ "$numcron" == "1" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "barname rizi noe kare gost: "
    echo -e "-----------------------------------"
    echo -e "[1] har ? saat rah andazi mojadad"
    echo -e "[2] rozane ? rahandazi mojadad"
    echo -e "-----------------------------------"
    read -p "lotfan entekhab konid: " numcrontype
    if [ "$numcrontype" == "1" ]; then
      echo -e "-----------------------------------"
      read -p "har ? rah andazi mojadad: " cronhr
      echo "0 0 */$cronhr * * ? * systemctl restart gost" >>/etc/crontab
      echo -e "tanzim mojadad zamanbandi shode ba movafaghiyat anjam shod！"
    elif [ "$numcrontype" == "2" ]; then
      echo -e "-----------------------------------"
      read -p "rozane ? rah andazi mojadad: " cronhr
      echo "0 0 $cronhr * * ? systemctl restart gost" >>/etc/crontab
      echo -e "tanzim mojadad zamanbandi shode ba movafaghiyat anjam shod！"
    else
      echo "type error, please try again"
      exit
    fi
  elif [ "$numcron" == "2" ]; then
    sed -i "/gost/d" /etc/crontab
    echo -e "rah andazi mojadad barname rizi hazf shode ast"
  else
    echo "type error, please try again"
    exit
  fi
}

update_sh() {
  ol_version=$(curl -L -s --connect-timeout 5 https://raw.githubusercontent.com/Cna-mrd/gost/master/gost.sh | grep "shell_version=" | head -1 | awk -F '=|"' '{print $3}')
  if [ -n "$ol_version" ]; then
    if [[ "$shell_version" != "$ol_version" ]]; then
      echo -e "noskhe jadid mojode [Y/N]?"
      read -r update_confirm
      case $update_confirm in
      [yY][eE][sS] | [yY])
        wget -N --no-check-certificate https://raw.githubusercontent.com/Cna-mrd/gost/master/gost.sh
        echo -e "berozresani kamel shod"
        exit 0
        ;;
      *) ;;

      esac
    else
      echo -e "                 ${Green_font_prefix}CNA MRD！${Font_color_suffix}"
    fi
  else
    echo -e "                 ${Red_font_prefix}akharin noskhe ra daryaft konid (------- CNA MRD --------)${Font_color_suffix}"
  fi
}

update_sh
echo && echo -e "                 gost script nasb ba yek click"${Red_font_prefix}[${shell_version}]${Font_color_suffix}"
  ----------- CNA MRD -----------
vizhegiha : (1) in script dar file haye  systemd va gost modiriyat mikonad
        (2)bedone niyaz be abzar digari(manand safhe namayesh)ghavanin forward be tor hamzaman
        (3)bad az rah andazi mojadad system dobare kar khod ra anjam midahad
  Function: (1) tcp+udp unencrypted forwarding, (2) Transit machine encrypted forwarding, (3) Landing machine decrypted docking forwarding
  help document：https://github.com/Cna-mrd/gost

 ${Green_font_prefix}1.${Font_color_suffix} nasb gost
 ${Green_font_prefix}2.${Font_color_suffix} nasb mojadad gost
 ${Green_font_prefix}3.${Font_color_suffix} hazf gost
————————————
 ${Green_font_prefix}4.${Font_color_suffix} start gost
 ${Green_font_prefix}5.${Font_color_suffix} stop gost
 ${Green_font_prefix}6.${Font_color_suffix} restart gost
————————————
 ${Green_font_prefix}7.${Font_color_suffix} Add gost forwarding configuration
 ${Green_font_prefix}8.${Font_color_suffix} View existing gost configuration
 ${Green_font_prefix}9.${Font_color_suffix} Delete a gost configuration
————————————
 ${Green_font_prefix}10.${Font_color_suffix} gost timed restart configuration
 ${Green_font_prefix}11.${Font_color_suffix} Custom TLS certificate configuration
————————————" && echo
read -e -p " Please enter the number [1-9]:" num
case "$num" in
1)
  Install_ct
  ;;
2)
  checknew
  ;;
3)
  Uninstall_ct
  ;;
4)
  Start_ct
  ;;
5)
  Stop_ct
  ;;
6)
  Restart_ct
  ;;
7)
  rawconf
  rm -rf /etc/gost/config.json
  confstart
  writeconf
  conflast
  systemctl restart gost
  echo -e "peykarbandi emal shode be shekle zir ast"
  echo -e "--------------------------------------------------------"
  show_all_conf
  ;;
8)
  show_all_conf
  ;;
9)
  show_all_conf
  read -p "lotfan shomare pekarbandi ke mikhahid hazf konid ra entekhab konid：" numdelete
  if echo $numdelete | grep -q '[0-9]'; then
    sed -i "${numdelete}d" $raw_conf_path
    rm -rf /etc/gost/config.json
    confstart
    writeconf
    conflast
    systemctl restart gost
    echo -e "peykarbandi hazf shod , servise dobare rah andazi shod"
  else
    echo "lotfan yek adad ra entekhab konid"
  fi
  ;;
10)
  cron_restart
  ;;
11)
  cert
  ;;
*)
  echo "lotfan yek adad ra entekhab konid [1-9]"
  ;;
esac
