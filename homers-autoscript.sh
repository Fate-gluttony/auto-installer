#!/usr/bin/env bash

# --------------------------------------------------------------------------- #
#    Script that automates the installation of OpenVPN, Privoxy and Squid.    #
#    Copyright (C) <2019>  <Homer Simpson :: PHCORNER.NET>                    #
#                                                                             #
#    This program is free software: you can redistribute it and/or modify     #
#    it under the terms of the GNU General Public License as published by     #
#    the Free Software Foundation, either version 3 of the License, or        #
#    (at your option) any later version.                                      #
#                                                                             #
#    This program is distributed in the hope that it will be useful,          #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of           #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            #
#    GNU General Public License for more details.                             #
#                                                                             #
#    You should have received a copy of the GNU General Public License        #
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.   #
#                                                                             #
#                                                                             #
# --------------------------------------------------------------------------- #

[[ "$EUID" -ne 0 ]] && { echo -e "This script needs to be run as root. Exiting...\n"; exit 1; }

INSTALLER="$(basename $0)"
OS_RELEASE_FILE="/etc/os-release"
OS=$(grep PRETTY_NAME $OS_RELEASE_FILE | cut -d'=' -f2 | cut -d' ' -f1 | tr -d '"')
OS_VERSION_ID=$(grep VERSION_ID $OS_RELEASE_FILE | cut -d'=' -f2 | tr -d '"')
TARGET_OS=$(echo "$OS $OS_VERSION_ID")
PACKAGES=( firewalld tmux squid privoxy bash-completion wget curl openvpn unzip zip postfix )
EXTERNAL_IP=
EXTERNAL_INT=
MYEMAIL=
ZONE=
CONFIRM=
SELINUX_CONFIG="/etc/selinux/config"
DATE=$(date +%d-%b-%Y)
: ${DAY:=$(date +%d)}
: ${HOUR:=$(date +%H:%M)}
MAILX_ARG=
NOGROUP="nogroup"
OVPN_COUNT=5
OVPN_PORT="1194"

get_email() {
    read -rp "Enter email: " MYEMAIL
    while ([[ -z $MYEMAIL ]]); do
        echo "Can't have an empty email address"
        read -rp "Enter email: " MYEMAIL
    done
    read -rp "Confirm (y/n): " CONFIRM
    while ([[ x$CONFIRM != 'xY' ]] && [[ x$CONFIRM != 'xy' ]]); do
    [[ x$CONFIRM == 'xN' ]] || [[ x$CONFIRM == 'xn' ]] && { $(get_email); break; }
    read -rp "Incorrect reply. Confirm (y/n): " CONFIRM
    done
}

menu() {
    echo
cat <<EOF
+-----------------------------------------------------------------+
|               OpenVPN, SQUID & PRIVOXY installer                |
|       ~ brought to you by Homer Simpson :: phcorner.net ~       |
+-----------------------------------------------------------------+
You will be notified via email once the installation is complete.
EOF
}

append_dns() {
    echo "Appending 1.1.1.1 and 1.0.0.1 into the DNS resolvers list..."
    if [[ $OS == "openSUSE" ]]; then
      sed -i 's/^\(NETCONFIG_DNS_STATIC_SERVERS="\)"/\11.1.1.1 1.0.0.1"/' /etc/sysconfig/network/config
    else
      echo -e "nameserver 1.1.1.1\nnameserver 1.0.0.1" > /etc/resolv.conf
    fi
}

get_ip() {
    export EXTERNAL_INT="$(cut -d' ' -f5 <(ip -4 route ls default))"
    export EXTERNAL_IP="$(ip -4 addr ls $EXTERNAL_INT | head -2 | tail -1 | cut -d' ' -f6 | cut -d'/' -f1)"
}

setup_firewall() {
    [[ x$(systemctl is-enabled firewalld.service) != "xenabled" ]] && systemctl enable firewalld.service; sleep 2; systemctl start firewalld.service
    echo "[EXTERNAL IP]: $EXTERNAL_IP"
    echo "[EXTERNAL INTERFACE]: $EXTERNAL_INT"
    [[ x$(firewall-cmd --get-default) != "xpublic" ]] && firewall-cmd --quiet --set-default=public
    ZONE=$(firewall-cmd --get-zone-of-interface=${EXTERNAL_INT})
    [[ x${ZONE} != "xpublic" ]] && firewall-cmd --quiet --permanent --zone=public --change-interface=${EXTERNAL_INT}; sleep 2
    echo "[ZONE]: ${ZONE}"
cat <<EOF
  Allowing openVPN:1194, privoxy:8118 and squid:3128 ports through the firewall
  Please note that this might not be the most secure setup!
EOF
    firewall-cmd --quiet --permanent --zone=${ZONE} --add-service=squid
    firewall-cmd --quiet --permanent --zone=${ZONE} --add-service=privoxy
    firewall-cmd --quiet --permanent --zone=${ZONE} --add-service=openvpn
    firewall-cmd --quiet --permanent --zone=${ZONE} --add-service=http
    firewall-cmd --quiet --permanent --zone=${ZONE} --add-service=jenkins
    firewall-cmd --quiet --permanent --zone=${ZONE} --add-port=1194/tcp
    firewall-cmd --quiet --permanent --zone=${ZONE} --add-masquerade
    sleep 2
    systemctl restart firewalld
    echo "Verifying if openVPN, privoxy, squid and http ports are allowed through the firewall..."
    echo -ne "[Allowed services]: $(firewall-cmd --zone=${ZONE} --list-services)\n"
}

setup_suse() {
    zypper update -y
    zypper install "${PACKAGES[@]}"
}

setup_centos() {
    yum -y update
    SYSTEMD_RESOLVED="systemd-resolved"
    yum install -y epel-release; sleep 2
    yum install -y "${PACKAGES[@]}" "${SYSTEMD_RESOLVED}" postfix-{perl-scripts,sysvinit} mailx
}

setup_debian() {
    SYSTEMD_RESOLVED="openvpn-systemd-resolved"
    DEBIAN_FRONTEND="noninteractive" apt-get update && apt-get upgrade -y
    DEBIAN_FRONTEND="noninteractive" apt-get install -y "${PACKAGES[@]}" "${SYSTEMD_RESOLVED}" mailutils
    sed -i '/^script-security/ a\up /etc/openvpn/update-systemd-resolved\ndown /etc/openvpn/update-systemd-resolved' /etc/openvpn/client-ovpn.d/template.txt
    sleep 2
}

setup_privoxy() {
    local PRIVOXY_CONFIG="/etc/privoxy/config"
    [[ -f $PRIVOXY_CONFIG ]] && { echo "Renaming the old config to ${PRIVOXY_CONFIG}.${DATE}-${HOUR}"; mv ${PRIVOXY_CONFIG}{,.${DATE}-${HOUR}}; }
cat << EOF > ${PRIVOXY_CONFIG}
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address  ${EXTERNAL_IP}:8118
toggle  1
enable-remote-toggle  0
enable-remote-http-toggle  0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries  1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 ${EXTERNAL_IP}
EOF
}

setup_squid() {
    local SQUID_CONFIG="/etc/squid/squid.conf"
    [[ -f $SQUID_CONFIG ]] && { echo "Renaming the old config to ${SQUID_CONFIG}.${DATE}-${HOUR}"; mv ${SQUID_CONFIG}{,.${DATE}-${HOUR}}; }
cat << EOF > ${SQUID_CONFIG}
visible_hostname squid.proxy
acl SSL_ports port 1194         # openVPN
acl Safe_ports port 1194        # openVPN
acl CONNECT method CONNECT
via off
forwarded_for delete
request_header_access Authorization allow all
request_header_access Proxy-Authorization allow all
request_header_access Cache-Control allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Connection allow all
request_header_access X-Forwarded-For deny all
request_header_access Via deny all
request_header_access Referer deny all
request_header_access All deny all
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost
http_access deny all
http_port 127.0.0.1:3127
http_port ${EXTERNAL_IP}:8080
cache deny all
shutdown_lifetime 5 seconds
EOF
}

setup_openvpn() {
    [[ ! -d /var/log/openvpn ]] && mkdir /var/log/openvpn
    OPENVPN_DIR="/etc/openvpn"
    EASYRSA_ZIP="$OPENVPN_DIR/easy-rsa3.zip"
    EASYRSA_DIR="$OPENVPN_DIR/easyrsa3"
    if [[ -d $OPENVPN_DIR ]]; then
        local OPENVPN_CONFIG="/etc/openvpn/server/server.conf"
        [[ -f $OPENVPN_CONFIG ]] && { echo "Renaming the old config to ${OPENVPN_CONFIG}.${DATE}-${HOUR}"; mv ${OPENVPN_CONFIG}{,.${DATE}-${HOUR}}; }
        cd $OPENVPN_DIR
        wget -q4O $EASYRSA_ZIP https://github.com/OpenVPN/easy-rsa/archive/master.zip
        unzip -qq $EASYRSA_ZIP && sleep 2; mv easy-rsa-master/easyrsa3 .
        rm -rf ${EASYRSA_ZIP}
    fi
    cd ${EASYRSA_DIR}
cat << EOF > vars
if [ -z "\${EASYRSA_CALLER}" ]; then
    echo "You appear to be sourcing an Easy-RSA 'vars' file." >&2
    echo "This is no longer necessary and is disallowed. See the section called" >&2
    echo "'How to use this file' near the top comments for more details." >&2
    return 1
fi

set_var EASYRSA_DN     "org"
set_var EASYRSA_REQ_COUNTRY     "PH"
set_var EASYRSA_REQ_PROVINCE    "Manila"
set_var EASYRSA_REQ_CITY        "Manila"
set_var EASYRSA_REQ_ORG "WWW.PHCORNER.NET"
set_var EASYRSA_REQ_EMAIL       "homer.simpson@highway-tohell.com"
set_var EASYRSA_REQ_OU          "My Organizational Unit"
set_var EASYRSA_REQ_CN          "My Common Name"
set_var EASYRSA_KEY_SIZE        2048
set_var EASYRSA_ALGO            rsa
set_var EASYRSA_CA_EXPIRE       3650
set_var EASYRSA_CERT_EXPIRE     1080
set_var EASYRSA_BATCH "yes"
EOF

    sleep 2
    ${EASYRSA_DIR}/easyrsa --batch init-pki
    ${EASYRSA_DIR}/easyrsa --batch build-ca nopass
    ${EASYRSA_DIR}/easyrsa --batch gen-req server nopass
    ${EASYRSA_DIR}/easyrsa --batch sign-req server server
    ${EASYRSA_DIR}/easyrsa --batch gen-dh
    cp ${EASYRSA_DIR}/pki/{dh.pem,ca.crt,issued/server.crt,private/server.key} ${OPENVPN_DIR}
	chmod go= ${OPENVPN_DIR}/server.key 2> /dev/null
    rm -rf ${OPENVPN_DIR}/easy-rsa-master 2> /dev/null

cat << EOF > ${OPENVPN_DIR}/server.conf
local 127.0.0.1
port 1194
proto tcp-server
dev tun
remote-cert-tls client
ca ca.crt
cert server.crt
key server.key  # This file should be kept secret
dh dh.pem
auth sha1
server 10.66.66.0 255.255.255.0
script-security 2
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "redirect-gateway def1"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
keepalive 10 120
cipher AES-128-CBC
compress lz4-v2
push "compress lz4-v2"
max-clients ${OVPN_COUNT}
user nobody
group ${NOGROUP}
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log-append  /var/log/openvpn/openvpn.log
verb 2
mute 20
sndbuf 393216
rcvbuf 393216
push "sndbuf 393216"
push "rcvbuf 393216"
;explicit-exit-notify 1 # Can only be used on udp
link-mtu 1440
EOF

VIA_PORT=( 8118 8080 )
TEMPLATE="${CLIENT_OVPN}/template.txt"
CLIENT_OVPN="${OPENVPN_DIR}/client-ovpn.d"
[[ ! -d ${CLIENT_OVPN} ]] && mkdir ${CLIENT_OVPN}
cat << EOF > ${TEMPLATE}
client
dev tun
proto tcp-client
remote 127.0.0.1 1194
pull
comp-lzo # UDP only
auth sha1
remote-cert-tls server
verb 2
mute 2
redirect-gateway def1
script-security 2
cipher AES-128-CBC
dhcp-option DNS 208.67.222.222
dhcp-option DNS 1.1.1.1
dhcp-option DNS 1.0.0.1
http-proxy ${EXTERNAL_IP} 8080
http-proxy-option VERSION 1.1
http-proxy-option CUSTOM-HEADER "CONNECT HTTP/1.1"
link-mtu 1440
EOF
    sleep 2
    for i in $(seq -ws' ' 1 ${OVPN_COUNT}); do
        CURRENT="${CLIENT_OVPN}/client${i}.ovpn"
        ${EASYRSA_DIR}/easyrsa --batch build-client-full client${i} nopass
        cat ${TEMPLATE} > ${CURRENT}
        echo >> ${CURRENT}
        echo "<ca>" >> ${CURRENT}
        sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' ${OPENVPN_DIR}/ca.crt >> ${CURRENT}
        echo "</ca>" >> ${CURRENT}
        echo >> ${CURRENT}
        echo "<cert>" >> ${CURRENT}
        sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' ${EASYRSA_DIR}/pki/issued/client${i}.crt >> ${CURRENT}
        echo "</cert>" >> ${CURRENT}
        echo >> ${CURRENT}
        echo "<key>" >> ${CURRENT}
        sed -n '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/p' ${EASYRSA_DIR}/pki/private/client${i}.key >> ${CURRENT}
        echo "</key>" >> ${CURRENT}
    done
    chmod -R go= ${CLIENT_OVPN}
    zip ${CLIENT_OVPN}/myovpns.zip ${CLIENT_OVPN}/*.ovpn
}

mail_report() {
  MAILER=$(which mailx)
  firewall-cmd --zone=public --list-all | tee -a ${REPORT}
  echo 'Setup report + OVPN configs. Enjoy!' | ${MAILER} -s "[${EXTERNAL_IP}] Report of openVPN, privoxy and squid installation on ${OS}-${OS_VERSION_ID} on $(date +%d-%b-%Y)" -${1} ${REPORT} -${1} /etc/openvpn/client-ovpn.d/myovpns.zip -- ${MYEMAIL}
}

post_install_check() {
    REPORT="/root/setup-report.txt"
    systemctl enable --now {firewalld,squid,privoxy,openvpn@server}.service
    systemctl start --now {firewalld,squid,privoxy,openvpn@server}.service
cat << EOF | tee -a ${REPORT}
$(echo -e "+----------------------------------------+\n")
$(echo -e "|---- PERFORMING POST-INSTALL CHECKS ----|\n")
$(echo -e "+========================================+\n")
$(echo -e "\n  Checking for listening ports...")
$(ss -4tlnp "( sport = :22 or sport = :1194 or sport = :8118 or sport = :3128 or sport = :8080 )")
$(echo -e "\nChecking allowed services through the firewall:") $(firewall-cmd --zone=${ZOME} --list-services)
$(echo)
EOF
  case "$TARGET_OS" in
    Debian*)
      dpkg -l "${PACKAGES[@]}" | tail +4 | tee -a ${REPORT}
      echo | tee -a ${REPORT}
      mail_report "A"
      ;;
    CentOS*)
      yum -q list installed "${PACKAGES[@]}" | tee -a $REPORT
      echo | tee -a ${REPORT}
      mail_report "a"
      ;;
    openSUSE*)
      zypper search -itpackage "${PACKAGES[@]}" | tee -a $REPORT
      echo | tee -a ${REPORT}
      mail_report "a"
      ;;
    esac
}

main_func() {
    menu
    [[ $(pgrep apt) ]] && { echo "A background apt process is running. Please re-try in 2-5 minutes"; exit 1; }
    get_email
    case "${TARGET_OS}" in
        Debian*)
            echo "Distro: $TARGET_OS"
            MAILX_ARG="A"
            setup_debian
            ;;
        CentOS*)
            echo "Distro: $TARGET_OS"
            NOGROUP="nobody"
            MAILX_ARG="a"
            setup_centos
            ;;
        openSUSE*)
            echo "Distro: $TARGET_OS"
            NOGROUP="nobody"
            setup_suse
            ;;
        *)
            echo "Unknown distro. Exiting..."
            exit 1
            ;;
      esac

    echo "SYSTEMD_RESOLVED: $SYSTEMD_RESOLVED" | tee -a ${REPORT}
    if (grep '^\s*IndividualCalls=no' /etc/firewalld/firewalld.conf); then
       sed -i 's/^\s*\(IndividualCalls=\)no/\1yes/' /etc/firewalld/firewalld.conf
    fi
    #echo -e "\n\nAdjusting TIMEZONE to Manila/PH"; rm -rf /etc/localtime; ln -sf /usr/share/zoneinfo/Asia/Manila /etc/localtime

    if (! grep '^\s*net.ipv4.ip_forward\s*=\s*1' /etc/sysctl.{conf,d/*.conf}); then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/homers-custom.conf
        echo "net.ipv6.conf.${EXTERNAL_INT}.forwarding=1" >> /etc/sysctl.d/homers-custom.conf
    fi

    if  ([[ -f ${SELINUX_CONFIG} ]]); then
        if (grep '^\s*SELINUX\s*=\s*enforcing' ${SELINUX_CONFIG}); then
            sed -i 's/^\s*\(SELINUX=\).\+/\1permissive/' ${SELINUX_CONFIG}
        fi
    fi

    get_ip
    postconf -e "inet_interfaces = loopback-only"; sleep 2
    systemctl stop postfix.service; sleep 2; systemctl start postfix
    setup_firewall
    setup_openvpn
    setup_privoxy
    setup_squid
#    append_dns
    post_install_check
    echo -e "\nNow rebooting the machine."
    reboot
}

main_func
