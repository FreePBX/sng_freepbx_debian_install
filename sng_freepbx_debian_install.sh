#!/bin/bash
#####################################################################################
# * Copyright 2024 by Sangoma Technologies
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3.0
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# @author kgupta@sangoma.com
#
# This FreePBX install script and all concepts are property of
# Sangoma Technologies.
# This install script is free to use for installing FreePBX
# along with dependent packages only but carries no guarantee on performance
# and is used at your own risk.  This script carries NO WARRANTY.
#####################################################################################
#                                               FreePBX 17                          #
#####################################################################################
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -e
SCRIPTVER="1.3"
ASTVERSION=21
AACVERSION="2.0.1-1"
PHPVERSION="8.2"
LOG_FOLDER="/var/log/pbx"
LOG_FILE="${LOG_FOLDER}/freepbx17-install-$(date '+%Y.%m.%d-%H.%M.%S').log"
DISTRIBUTION="$(lsb_release -is)"
log=$LOG_FILE

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

mkdir -p "${LOG_FOLDER}"
echo "" > $log

# Get parameters
POSITIONAL_ARGS=()

#Comparing version
compare_version() {
        if dpkg --compare-versions "$1" "gt" "$2"; then
                result=0
        elif dpkg --compare-versions "$1" "lt" "$2"; then
                result=1
        else
                result=2
        fi
}

check_version() {
    # Fetching latest version and checksum
    REPO_URL="https://github.com/FreePBX/sng_freepbx_debian_install/raw/master"
    wget -q -O /tmp/sng_freepbx_debian_install_latest_from_github.sh "$REPO_URL/sng_freepbx_debian_install.sh"

    latest_version=$(grep '^SCRIPTVER="' /tmp/sng_freepbx_debian_install_latest_from_github.sh | awk -F'"' '{print $2}')
    latest_checksum=$(sha256sum /tmp/sng_freepbx_debian_install_latest_from_github.sh | awk '{print $1}')

    # Cleaning up downloaded file
    rm -f /tmp/sng_freepbx_debian_install_latest_from_github.sh

    compare_version $SCRIPTVER $latest_version

    case $result in
            0)
                echo "Your version ($SCRIPTVER) of installation script is ahead of the latest version ($latest_version) as present on the GitHub. We recommend you to Download the version present in the GitHub."
                echo "Use '$0 --skipversion' to skip the version check"
                exit 1
            ;;

            1)
                echo "A newer version ($latest_version) of installation script is available on GitHub. We recommend you to update it or use the latest one from the GitHub."
                echo "Use '$0 --skipversion' to skip the version check."
                exit 0
            ;;

            2)
                local_checksum=$(sha256sum "$0" | awk '{print $1}')
                if [[ "$latest_checksum" != "$local_checksum" ]]; then
                        echo "Changes are detected between the local installation script and the latest installation script as present on GitHub. We recommend you to please use the latest installation script as present on GitHub."
                        echo "Use '$0 --skipversion' to skip the version check"
                        exit 0
                else
                        echo "Perfect! You're already running the latest version."
                fi
            ;;
        esac
}
while [[ $# -gt 0 ]]; do
	case $1 in
		--testing)
			testrepo=true
			shift # past argument
			;;
		--nofreepbx)
			nofpbx=true
			shift # past argument
			;;
		--noasterisk)
			noast=true
			shift # past argument
			;;
		--noioncube)
			noioncube=true
			shift # past argument
			;;
                --skipversion)
                        skipversion=true
                        shift # past argument
                        ;;
		--dahdi)
                        dahdi=true
                        shift # past argument
                        ;;
		-*|--*)
			echo "Unknown option $1"
			exit 1
			;;
		*)
			POSITIONAL_ARGS+=("$1") # save positional arg
			shift # past argument
			;;
	esac
done

if [[ $skipversion ]]; then
    echo "Skipping version check..."
else
    # Perform version check if --skipversion is not provided
    echo "Performing version check..."
    check_version
fi


#Helpers APIs
exec 2>>${LOG_FILE}

# Function to log messages
log() {
	echo "$(date +"%Y-%m-%d %T") - $*" >> "$LOG_FILE"
}

message() {
	echo "$(date +"%Y-%m-%d %T") - $*"
	log "$*"
}

#Function to record and display the current step
setCurrentStep () {
	currentStep="$1"
	message "${currentStep}"
}

# Function to cleanup installation
terminate() {
	# removing pid file
	message "Exiting script"
	rm -f "$pidfile"
}

#Function to log error and location
errorHandler() {
	log "****** INSTALLATION FAILED *****"
	message "Installation failed at step ${currentStep}. Please check log ${LOG_FILE} for details."
	message "Error at line: $1 exiting with code $2 (last command was: $3)"
	exit "$2"
}

# Checking if the package is already installed or not
isinstalled() {
	PKG_OK=$(/usr/bin/dpkg-query -W --showformat='${Status}\n' "$@" 2>/dev/null|grep "install ok installed")
	if [ "" = "$PKG_OK" ]; then
		false
	else
		true
	fi
}

# Function to install the package
pkg_install() {
	log "############################### "
	PKG=$@
	if isinstalled $PKG; then
		log "$PKG already present ...."
	else
		message "Installing $PKG ...."
		apt-get -y --ignore-missing -o DPkg::Options::="--force-confnew" -o Dpkg::Options::="--force-overwrite" install $PKG >> $log 2>&1
		if isinstalled $PKG; then
			message "$PKG installed successfully...."
		else
			message "$PKG failed to install ...."
			message "Exiting the installation process as dependent $PKG failed to install ...."
			terminate
		fi
	fi
	log "############################### "
}

# Function to install the mongodb
install_mongodb() {
	if isinstalled mongodb-org; then
		log "mongodb already installed ...."
	else
		message "Installing  mongodb...."
		# Ref - https://medium.com/@arun0808rana/mongodb-installation-on-debian-12-8001d0dafb56
		apt-get install -y mongodb-org >> "$log" 2>&1

		if isinstalled mongodb-org; then
			message "Mongodb installed successfully...."
		else
			message "Mongodb failed to install ...."
			exit 1
		fi
	fi
}


# Function to install the libfdk-aac
install_libfdk() {
      if isinstalled libfdk-aac2; then
            log "libfdk-aac2 already installed ...."
      else
            message "Installing libfdk-aac2...."
            apt-get install -y libfdk-aac2 >> "$log" 2>&1
      if isinstalled libfdk-aac2; then
            message "libfdk-aac2 installed successfully....."
      else
            message "libfdk-aac2 failed to install ...."
            exit 1
      fi
fi
}

# Function to install the asterisk and dependent packages
install_asterisk() {
	astver=$1
	ASTPKGS=("addons"
		"addons-bluetooth"
		"addons-core"
		"addons-mysql"
		"addons-ooh323"
		"core"
		"curl"
		"dahdi"
		"doc"
		"odbc"
		"ogg"
		"flite"
		"g729"
		"resample"
		"snmp"
		"speex"
		"sqlite3"
		"res-digium-phone"
		"voicemail"
	)

	# creating directories
	mkdir -p /var/lib/asterisk/moh
	pkg_install asterisk$astver

	for i in "${!ASTPKGS[@]}"; do
		pkg_install asterisk$astver-${ASTPKGS[$i]}
	done

	pkg_install asterisk$astver.0-freepbx-asterisk-modules
	pkg_install asterisk-version-switch
	pkg_install asterisk-sounds-*
}

setup_repositories() {
	#Add PHP repository
	wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
	if [ "${DISTRIBUTION}" = "Ubuntu" ]; then
	    add-apt-repository -y "ppa:ondrej/php" >> "$log" 2>&1
	    add-apt-repository -y "ppa:ondrej/apache2" >> "$log" 2>&1
	else
		add-apt-repository -y -S "deb [ arch=${arch} ] https://packages.sury.org/php/ $(lsb_release -sc) main" >> "$log" 2>&1
	fi

	apt-key del "9641 7C6E 0423 6E0A 986B  69EF DE82 7447 3C8D 0E52" >> "$log" 2>&1

	wget -qO - http://deb.freepbx.org/gpg/aptly-pubkey.asc | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/freepbx.gpg  >> "$log" 2>&1

	# Setting our default repo server
	if [ $testrepo ] ; then
		add-apt-repository -y -S "deb [ arch=${arch} ] http://deb.freepbx.org/freepbx17-dev bookworm main" >> "$log" 2>&1
		add-apt-repository -y -S "deb [ arch=${arch} ] http://deb.freepbx.org/freepbx17-dev bookworm main" >> "$log" 2>&1
	else
		add-apt-repository -y -S "deb [ arch=${arch} ] http://deb.freepbx.org/freepbx17-prod bookworm main" >> "$log" 2>&1
		add-apt-repository -y -S "deb [ arch=${arch} ] http://deb.freepbx.org/freepbx17-prod bookworm main" >> "$log" 2>&1
	fi

	wget -qO - https://pgp.mongodb.com/server-7.0.asc | gpg  --dearmor --yes -o /etc/apt/trusted.gpg.d/mongodb-server-7.0.gpg >> "$log" 2>&1
	add-apt-repository -y -S "deb [ arch=${arch} ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" >> "$log" 2>&1

      add-apt-repository -y -S "deb http://ftp.debian.org/debian/ stable main non-free" >> "$log" 2>&1

	setCurrentStep "Setting up Sangoma repository"
cat <<EOF> /etc/apt/preferences.d/99sangoma-fpbx-repository
# Allways prefer packages from deb.freepbx.org

Package: *
Pin: origin deb.freepbx.org
Pin-Priority: ${MIRROR_PRIO}
EOF
}

check_services() {
    services=("fail2ban" "iptables")
    for service in "${services[@]}"; do
        service_status=$(systemctl is-active "$service")
        if [[ "$service_status" != "active" ]]; then
            message "Service $service is not active. Please ensure it is running."
        fi
    done

    apache2_status=$(systemctl is-active apache2)
    if [[ "$apache2_status" == "active" ]]; then
        apache_process=$(netstat -anp | awk '$4 ~ /:80$/ {sub(/.*\//,"",$7); print $7}')
        if [ "$apache_process" == "apache2" ]; then
            message "Apache2 service is running on port 80."
        else
            message "Apache2 is not running in port 80."
        fi
    else
        message "The Apache2 service is not active. Please activate the service"
    fi
}

check_php_version() {
    php_version=$(php -v | grep built: | awk '{print $2}')
    if [[ "${php_version:0:3}" == "8.2" ]]; then
        message "Installed PHP version $php_version is compatible with FreePBX."
    else
        message "Installed PHP version  $php_version is not compatible with FreePBX. Please install PHP version '8.2.x'"
    fi
}

verify_module_status() {
    modules_list=$(fwconsole ma list | grep -Ewv "Enabled|----|Module|No repos")
    if [ -z "$modules_list" ]; then
        message "All Modules are Enabled."
    else
        message "List of modules which are not Enabled:"
        message "$modules_list"
    fi
}

# Function to check assigned ports for services
inspect_network_ports() {
    # Array of port and service pairs
    local ports_services=(
        82 restapps
        83 restapi
        81 ucp
        80 acp
        84 hpro
        "" leport
        "" sslrestapps
        "" sslrestapi
        "" sslucp
        "" sslacp
        "" sslhpro
        "" sslsngphone
    )

    for (( i=0; i<${#ports_services[@]}; i+=2 )); do
        port="${ports_services[i]}"
        service="${ports_services[i+1]}"
        port_set=$(fwconsole sa ports | grep "$service" | cut -d'|' -f 2 | tr -d '[:space:]')

        if [ "$port_set" == "$port" ]; then
            message "$service module is assigned to its default port."
        else
            message "$service module is expected to have port $port assigned instead of $port_set"
        fi
    done
}

inspect_running_processes() {
    processes=$(fwconsole pm2 --list |  grep -Ewv "online|----|Process")
    if [ -z "$processes" ]; then
        message "No Offline Processes found."
    else
        message "List of Offline processes:"
        message "$processes"
    fi
}

check_freepbx() {
     # Check if FreePBX is installed
    if ! dpkg -l | grep -q 'freepbx'; then
        message "FreePBX is not installed. Please install FreePBX to proceed."
    else
        verify_module_status
        inspect_network_ports
        inspect_running_processes
        inspect_job_status=$(fwconsole job --list)
        message "Job list : $inspect_job_status"
    fi
}

check_digium_phones_version() {
    installed_version=$(asterisk -rx 'digium_phones show version' | awk '/Version/{print $NF}' 2>/dev/null)
    if [[ -n "$installed_version" ]]; then
        required_version="21.0_3.6.8"
        present_version=$(echo "$installed_version" | sed 's/_/./g')
        required_version=$(echo "$required_version" | sed 's/_/./g')
        if dpkg --compare-versions "$present_version" "lt" "$required_version"; then
            message "A newer version of Digium Phones module is available."
        else
            message "Installed Digium Phones module version: ($installed_version)"
        fi
    else
        message "Failed to check Digium Phones module version."
    fi
}

check_asterisk() {
    if ! dpkg -l | grep -q 'asterisk'; then
        message "Asterisk is not installed. Please install Asterisk to proceed."
    else
        check_asterisk_version=$(asterisk -V)
        message "$check_asterisk_version"
	if asterisk -rx "module show" | grep -q "res_digium_phone.so"; then
            check_digium_phones_version
        else
            message "Digium Phones module is not loaded. Please make sure it is installed and loaded correctly."
        fi
    fi
}

################################################################################################################
MIRROR_PRIO=600
kernel=`uname -a`
arch=`dpkg --print-architecture`
host=`hostname`
fqdn="$(hostname -f)"

#Ensure the script is not running
pid="$$"
pidfile='/var/run/freepbx17_installer.pid'

if [ -f "$pidfile" ]; then
	log "Previous PID file found."
	if ps -p "${pid}" > /dev/null
	then
		message "FreePBX 17 installation process is already going on (PID=${pid}), hence not starting new process"
		exit 1;
	fi
	log "Removing stale PID file"
	rm -f "${pidfile}"
fi

setCurrentStep "Starting installation."
trap 'errorHandler "$LINENO" "$?" "$BASH_COMMAND"' ERR
trap "terminate" EXIT
echo "${pid}" > $pidfile

start=$(date +%s)
message "  Starting FreePBX 17 installation process for $host $kernel"
message "  Please refer to the $log to know the process..."
log "  Executing script v$SCRIPTVER ..."

setCurrentStep "Making sure installation is same"
# Fixing broken install
apt -y --fix-broken install >> $log 2>&1
apt autoremove -y >> "$log" 2>&1

# Adding iptables and postfix  inputs so "iptables-persistent" and postfix will not ask for the input
setCurrentStep "Setting up default configuration"
debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF
echo "postfix postfix/mailname string ${fqdn}" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

# Install below packages which is required to add the repository
pkg_install software-properties-common
pkg_install gnupg

setCurrentStep "Setting up repositories"
setup_repositories

setCurrentStep "Updating repository"
apt update >> $log 2>&1

# log the apt-cache policy
apt-cache policy  >> $log 2>&1



# Install dependent packages
setCurrentStep "Installing required packages"
DEPPKGS=("redis-server"
	"libsnmp-dev"
	"libtonezone-dev"
	"libpq-dev"
	"liblua5.2-dev"
	"libpri-dev"
	"libbluetooth-dev"
	"libunbound-dev"
	"libsybdb5"
	"libspeexdsp-dev"
	"libiksemel-dev"
	"libresample1-dev"
	"libgmime-3.0-dev"
	"libc-client2007e-dev"
	"dpkg-dev"
	"ghostscript"
	"libtiff-tools"
	"iptables-persistent"
	"net-tools"
	"rsyslog"
	"libavahi-client3"
	"nmap"
	"apache2"
	"zip"
	"incron"
	"chrony"
	"wget"
	"vim"
	"build-essential"
	"openssh-server"
	"apache2"
	"mariadb-server"
	"mariadb-client"
	"bison"
	"flex"
	"flite"
	"php${PHPVERSION}"
	"php${PHPVERSION}-curl"
	"php${PHPVERSION}-zip"
	"php${PHPVERSION}-redis"
	"php${PHPVERSION}-curl"
	"php${PHPVERSION}-cli"
	"php${PHPVERSION}-common"
	"php${PHPVERSION}-mysql"
	"php${PHPVERSION}-gd"
	"php${PHPVERSION}-mbstring"
	"php${PHPVERSION}-intl"
	"php${PHPVERSION}-xml"
	"php${PHPVERSION}-bz2"
	"php${PHPVERSION}-ldap"
	"php${PHPVERSION}-sqlite3"
	"php${PHPVERSION}-bcmath"
	"php-soap"
	"php-bcmath"
	"php-pear"
	"curl"
	"sox"
	"libncurses5-dev"
	"libssl-dev"
	"mpg123"
	"libxml2-dev"
	"libnewt-dev"
	"sqlite3"
	"libsqlite3-dev"
	"pkg-config"
	"automake"
	"libtool"
	"autoconf"
	"git"
	"unixodbc-dev"
	"uuid"
	"uuid-dev"
	"libasound2-dev"
	"libogg-dev"
	"libvorbis-dev"
	"libicu-dev"
	"libcurl4-openssl-dev"
	"odbc-mariadb"
	"libical-dev"
	"libneon27-dev"
	"libsrtp2-dev"
	"libspandsp-dev"
	"sudo"
	"subversion"
	"libtool-bin"
	"python-dev-is-python3"
	"unixodbc"
	"libjansson-dev"
	"nodejs"
	"npm"
	"ipset"
	"iptables"
	"fail2ban"
	"htop"
	"liburiparser-dev"
	"postfix"
	"tcpdump"
	"sngrep"
	"libavdevice-dev"
	"tftpd-hpa"
	"xinetd"
	"lame"
	"haproxy"
	"screen"
	"easy-rsa"
	"openvpn"
	"sysstat"
	"apt-transport-https"
	"lsb-release"
	"ca-certificates"
 	"cron"
)
for i in "${!DEPPKGS[@]}"; do
	pkg_install ${DEPPKGS[$i]}
done

# OpenVPN EasyRSA configuration
/usr/bin/make-cadir /etc/openvpn/easyrsa3
rm -f /etc/openvpn/easyrsa3/pki/vars
rm -f /etc/openvpn/easyrsa3/vars

# Install Dahdi card support if --dahdi option is provided
if [[ "$dahdi" == true ]]; then
    echo "Installing Dahdi card support..."
    kernel_version=`apt-cache show linux-headers-$(uname -r) | sed -n -e 's/Package: linux-headers-\\([[:digit:].-]*\\).*/\\1/' -e 's/-\$//p' | uniq`
    DAHDIPKGS=("asterisk21-dahdi"
           "dahdi-firmware"
           "dahdi-linux"
           "dahdi-linux-devel"
           "dahdi-tools"
           "libpri"
           "libpri-devel"
           "wanpipe"
           "wanpipe-devel"
           "dahdi-linux-kmod-${kernel_version}"
           "kmod-wanpipe-${kernel_version}"
	)

        for i in "${!DAHDIPKGS[@]}"; do
                pkg_install ${DAHDIPKGS[$i]}
        done
fi

# Install mongod
setCurrentStep "Setting up MongoDB"
install_mongodb

# Install libfdk
setCurrentStep "Setting up libfdk"
install_libfdk

setCurrentStep "Removing unnecessary packages"
apt autoremove -y >> "$log" 2>&1

execution_time="$(($(date +%s) - $start))"
message "Execution time to install all the dependent packages : $execution_time s"




setCurrentStep "Setting up folders and asterisk config"
groupExists="`getent group asterisk || echo ''`"
if [ "${groupExists}" = "" ]; then
	groupadd -r asterisk
fi

userExists="`getent passwd asterisk || echo ''`"
if [ "${userExists}" = "" ]; then
	useradd -r -g asterisk -d /home/asterisk -M -s /bin/bash asterisk
fi

# Adding asterisk to the sudoers list
#echo "%asterisk ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers

# Creating /tftpboot directory
mkdir -p /tftpboot
# Creating asterisk sound directory
mkdir -p /var/lib/asterisk/sounds
chown -R asterisk:asterisk /var/lib/asterisk

# Changing openssl to make it compatible with the katana
sed -i -e 's/^openssl_conf = openssl_init$/openssl_conf = default_conf/' /etc/ssl/openssl.cnf

isSSLConfigAdapted=$(grep "FreePBX 17 changes" /etc/ssl/openssl.cnf |wc -l)
if [ "0" = "${isSSLConfigAdapted}" ]; then
	cat <<EOF >> /etc/ssl/openssl.cnf
# FreePBX 17 changes - begin
[ default_conf ]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=1
# FreePBX 17 changes - end
EOF
fi

#Disabling ipv6 to avoid localhost to resolving to ipv6 address (which could break nodeJs)
isIPv6Disabled=$(grep "FreePBX 17 changes" /etc/sysctl.conf |wc -l)
if [ "0" = "${isIPv6Disabled}" ]; then
	cat <<EOF >> /etc/sysctl.conf
# FreePBX 17 changes - begin
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
# FreePBX 17 changes - end
EOF
	/usr/sbin/sysctl -p >> $log 2>&1
fi


# Setting screen configuration
isScreenRcAdapted=$(grep "FreePBX 17 changes" /root/.screenrc |wc -l)
if [ "0" = "${isScreenRcAdapted}" ]; then
	cat <<EOF >> /root/.screenrc
# FreePBX 17 changes - begin
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{=kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B}%Y-%m-%d %{W}%c %{g}]'
# FreePBX 17 changes - end
EOF
fi


# Setting VIM configuration for mouse copy paste
isVimRcAdapted=$(grep "FreePBX 17 changes" /etc/vim/vimrc.local |wc -l)
if [ "0" = "${isVimRcAdapted}" ]; then
	VIMRUNTIME=`vim -e -T dumb --cmd 'exe "set t_cm=\<C-M>"|echo $VIMRUNTIME|quit' | tr -d '\015' `
	VIMRUNTIME_FOLDER=`echo $VIMRUNTIME | sed 's/ //g'`

	cat <<EOF >> /etc/vim/vimrc.local
" FreePBX 17 changes - begin
" This file loads the default vim options at the beginning and prevents
" that they are being loaded again later. All other options that will be set,
" are added, or overwrite the default settings. Add as many options as you
" whish at the end of this file.

" Load the defaults
source $VIMRUNTIME_FOLDER/defaults.vim

" Prevent the defaults from being loaded again later, if the user doesn't
" have a local vimrc (~/.vimrc)
let skip_defaults_vim = 1


" Set more options (overwrites settings from /usr/share/vim/vim80/defaults.vim)
" Add as many options as you whish

" Set the mouse mode to 'r'
if has('mouse')
  set mouse=r
endif
" FreePBX 17 changes - end
EOF
fi


#chown -R asterisk:asterisk /etc/ssl

# Install Asterisk
if [ $noast ] ; then
	message "Skipping Asterisk installation due to noastrisk option"
else
	# TODO Need to check if asterisk installed already then remove that and install new ones.
	# Install Asterisk 21
	setCurrentStep "Installing Asterisk packages."
	install_asterisk $ASTVERSION
fi

# Install PBX dependent packages
setCurrentStep "Installing FreePBX packages"

# Install ionCube
if [ $noioncube ] ; then
	message "Skipping ionCube installation due to noioncube option"
else
	# TODO Need to check if ioncube installed already then remove that and install new ones.
	# Install ionCube
	setCurrentStep "Installing ionCube packages."
	pkg_install ioncube-loader-82
fi

FPBXPKGS=("sysadmin17"
	   "sangoma-pbx17"
	   "ffmpeg"
   )
for i in "${!FPBXPKGS[@]}"; do
	pkg_install ${FPBXPKGS[$i]}
done


#Enabling freepbx.ini file
setCurrentStep "Enabling modules."
/usr/sbin/phpenmod freepbx
mkdir -p /var/lib/php/session

#Creating default config files
mkdir -p /etc/asterisk
touch /etc/asterisk/extconfig_custom.conf
touch /etc/asterisk/extensions_override_freepbx.conf
touch /etc/asterisk/extensions_additional.conf
touch /etc/asterisk/extensions_custom.conf
chown -R asterisk:asterisk /etc/asterisk

setCurrentStep "Restating fail2ban"
log "Restarting fail2ban "
/usr/bin/systemctl restart fail2ban  >> $log


if [ $nofpbx ] ; then
	message "Skipping FreePBX 17 fresh tarball installation due to nofreepbx option"
else
	setCurrentStep "Installing FreePBX 17"
	pkg_install freepbx17

	# Reinstalling modules to ensure all the modules are enabled/installed
  setCurrentStep "Installing Sysadmin module"
  fwconsole ma install sysadmin >> $log 2>&1

  #Not installing sangoma connect result in failure of first installlocal
  setCurrentStep "Installing sangomaconnectmodule"
  fwconsole ma install sangomaconnect>> $log 2>&1

  setCurrentStep "Installing install local module"
  fwconsole ma installlocal >> $log 2>&1

  setCurrentStep "Upgrading FreePBX 17 modules"
  fwconsole ma upgradeall >> $log 2>&1

  setCurrentStep "reloading and restarting FreePBX 17"
  fwconsole reload >> $log 2>&1
  fwconsole restart >> $log 2>&1
fi


setCurrentStep "Wrapping up the installation process"
systemctl daemon-reload >> "$log" 2>&1
if [ ! $nofpbx ] ; then
  systemctl enable freepbx >> "$log" 2>&1
fi

#delete apache2 index.html as we do not need that file
rm -f /var/www/html/index.html

#enable apache mod ssl
/usr/sbin/a2enmod ssl  >> "$log" 2>&1

#enable apache mod expires
/usr/sbin/a2enmod expires  >> "$log" 2>&1

#enable apache
a2enmod rewrite >> "$log" 2>&1

#Enabling freepbx apache configuration
a2ensite freepbx.conf

#Setting postfix size to 100MB
/usr/sbin/postconf -e message_size_limit=102400000

# Disable expose_php for provide less information to attacker
sed -i 's/\(^expose_php = \).*/\1Off/' /etc/php/${PHPVERSION}/apache2/php.ini

# Disable ServerTokens and ServerSignature for provide less information to attacker
sed -i 's/\(^ServerTokens \).*/\1Prod/' /etc/apache2/conf-available/security.conf
sed -i 's/\(^ServerSignature \).*/\1Off/' /etc/apache2/conf-available/security.conf

# Restart apache2
systemctl restart apache2 >> "$log" 2>&1

# Refresh signatures
if [ ! $nofpbx ] ; then
  fwconsole ma refreshsignatures >> "$log" 2>&1
fi

#Do not want to upgrade initial(first time setup) packages
if [ ! $nofpbx ] ; then
	apt-mark hold freepbx17
fi
apt-mark hold sangoma-pbx17

setCurrentStep "Installation successful."

############ TODO - POST INSTALL VALIDATION ############################################
# Commands for post-installation validation
# Disable automatic script termination upon encountering non-zero exit code to prevent premature termination.
set +e
setCurrentStep "Post-installation validation"

check_services

check_php_version

if [ ! $nofpbx ] ; then
 check_freepbx
fi

check_asterisk

execution_time="$(($(date +%s) - $start))"
message "Total script Execution Time: $execution_time"
message "Finished FreePBX 17 installation process for $host $kernel"
message "Join us on the FreePBX Community Forum: https://community.freepbx.org/ ";

if [ ! $nofpbx ] ; then
  fwconsole motd
fi
