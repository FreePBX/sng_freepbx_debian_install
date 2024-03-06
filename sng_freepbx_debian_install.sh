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
# along with dependent packages only but carries no guarnatee on performance
# and is used at your own risk.  This script carries NO WARRANTY.
#####################################################################################
#                                               FreePBX 17              #
#####################################################################################
SCRIPTVER="1.0"
ASTVERSION=21
LOG_FILE='/var/log/pbx/freepbx17-install.log'
log=$LOG_FILE
mkdir -p '/var/log/pbx/'
echo "" > $log
#####################################################################################
# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi
#####################################################################################
POSITIONAL_ARGS=()

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


################################################################################################################
################################################################################################################
#Helpers APIs
exec 2>>${LOG_FILE}

# Function to log messages
log() {
	echo "$(date +"%Y-%m-%d %T") - $*" >> "$LOG_FILE"
}

message() {
	echo "$(date +"%Y-%m-%d %T") - $*"
	echo "$(date +"%Y-%m-%d %T") - $*" >> "$LOG_FILE"
}

# Function to exit the process 
terminate() {
	# removing pid file
	rm -rf $pidfile
	exit 0;
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
		message "Installing $PKG Now ...."
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
		apt-get -y --ignore-missing install gnupg curl >> "$log" 2>&1
		curl -fsSL https://pgp.mongodb.com/server-7.0.asc | gpg  --dearmor -o /etc/apt/trusted.gpg.d/mongodb-server-7.0.gpg >> "$log" 2>&1
		echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list >> "$log" 2>&1
		apt-get update >> "$log" 2>&1
		apt-get install -y mongodb-org >> "$log" 2>&1

		if isinstalled mongodb-org; then
			message "Mongodb installed successfully...."
		else 
			message "Mongodb failed to install ...."
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

################################################################################################################
################################################################################################################
MIRROR_PRIO=600
kernel=`uname -a`
host=`hostname`
pidfile='/var/run/freepbx17.pid'


if [ -f "$pidfile" ]; then
	message "FreePBX 17 installation process is already going on, hence not starting new process"
	message "If FreePBX 17 installation process is NOT running then delete $pidfile file and try again."
	exit 1;
fi

start=$(date +%s.%N)
message "  Starting FreePBX 17 installation process for $host $kernel"
message "  Please refer to the $log to know the process..."
log "  Executing script v$SCRIPTVER ..."
touch $pidfile

################################################################################################################

########################################################################################
# Step-1 : Install dependent packages
########################################################################################
#
log "############################### "
message "###### STEP-1 Installing dependent packages process - BEGIN ######################### "

# Fixing broken install
apt --fix-broken install >> $log 2>&1
# update repos
apt update >> $log 2>&1


# Adding iptables and postfix  inputs so "iptables-persistent" and postfix will not ask for the input 
debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF
echo "postfix postfix/mailname string my.hostname.example" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

# Install dependent packages
DEPPKGS=("redis-server" 
	"bc" 
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
	"php8.2" 
	"php8.2-curl" 
	"php8.2-zip" 
	"php8.2-redis" 
	"php8.2-curl" 
	"php8.2-cli" 
	"php8.2-common" 
	"php8.2-mysql" 
	"php8.2-gd" 
	"php8.2-mbstring" 
	"php8.2-intl" 
	"php8.2-xml" 
	"php8.2-bz2" 
	"php8.2-ldap" 
	"php-soap" 
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
)

for i in "${!DEPPKGS[@]}"; do
	pkg_install ${DEPPKGS[$i]}
done

# Install mongod
install_mongodb

# Install libfdk
if isinstalled libfdk-aac2; then
	log "libfdk-aac2 already present...."
else
	wget http://ftp.us.debian.org/debian/pool/non-free/f/fdk-aac/libfdk-aac2_2.0.1-1_amd64.deb -O /tmp/libfdk-aac2_2.0.1-1_amd64.deb >> "$log" 2>&1
	wget http://ftp.us.debian.org/debian/pool/non-free/f/fdk-aac/libfdk-aac-dev_2.0.1-1_amd64.deb -O /tmp/libfdk-aac-dev_2.0.1-1_amd64.deb >> "$log" 2>&1
	dpkg -i /tmp/libfdk-aac2_2.0.1-1_amd64.deb >> "$log" 2>&1
	dpkg -i /tmp/libfdk-aac-dev_2.0.1-1_amd64.deb >> "$log" 2>&1
fi

apt autoremove -y >> "$log" 2>&1

duration=$(echo "$(date +%s.%N) - $start" | bc)
execution_time=`printf "%.2f seconds" $duration`
message "Execution time to install all the dependent packages : $execution_time"
message " ###### STEP-1 END #########################  "
########################################################################################
# Step-2 : Perform pre-requisite steps
########################################################################################
########################################################################################
log "############################### "
message "###### STEP-2 Performing pre requisite steps BEGIN ######################### "

# Add preference file
cat <<EOF> /etc/apt/preferences.d/99sangoma-fpbx-repository
# Allways prefer packages from deb.freepbx.org

Package: *
Pin: origin deb.freepbx.org
Pin-Priority: ${MIRROR_PRIO}
EOF

pkg_install software-properties-common
pkg_install gnupg

# Delete old key 
apt-key del "9641 7C6E 0423 6E0A 986B  69EF DE82 7447 3C8D 0E52"

wget -qO - http://deb.freepbx.org/gpg/aptly-pubkey.asc | apt-key add - >> "$log" 2>&1

message " ###### STEP-2 END #########################  "

groupadd -r asterisk
useradd -r -g asterisk -d /home/asterisk -M -s /bin/bash asterisk

# Adding asterisk to the sudoers list
#echo "%asterisk ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers

# Creating /tftpboot directory
mkdir -p /tftpboot
# Creating asterisk sound directory 
mkdir -p /var/lib/asterisk/sounds
chown -R asterisk:asterisk /var/lib/asterisk

# Changing openssl to make it compatible with the katana
sed -i -e 's/^openssl_conf = openssl_init$/openssl_conf = default_conf/' /etc/ssl/openssl.cnf

cat <<EOF >> /etc/ssl/openssl.cnf
[ default_conf ]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=1
EOF


#Disabling ipv6 to avoid localhost to resolving to ipv6 address (which could break nodeJs)
cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
/usr/sbin/sysctl -p >> $log 2>&1


# Setting screen configuration 
cat <<EOF >> /root/.screenrc
hardstatus alwayslastline
hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{=kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B}%Y-%m-%d %{W}%c %{g}]'
EOF


# Setting VIM configuration for mouse copy paste
VIMRUNTIME=`vim -e -T dumb --cmd 'exe "set t_cm=\<C-M>"|echo $VIMRUNTIME|quit' | tr -d '\015' `

VIMRUNTIME_FOLDER=`echo $VIMRUNTIME | sed 's/ //g'`

cat <<EOF >> /etc/vim/vimrc.local
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
EOF

message "###### STEP-2 END ######################### "

########################################################################################
# Step-3 : Set the Sangoma Debian repository to download Sangoma freepbx17 packages
########################################################################################
#
log "############################### "
message "###### STEP-3 Installing Sangoma dependent packages BEGIN ######################### "

# Setting our default repo server
if [ $testrepo ] ; then
	add-apt-repository -y -S 'deb http://deb.freepbx.org/freepbx17-dev bookworm main' >> "$log" 2>&1
	add-apt-repository -y -S 'deb http://deb.freepbx.org/freepbx17-dev bookworm main' >> "$log" 2>&1
else
	add-apt-repository -y -S 'deb http://deb.freepbx.org/freepbx17-prod bookworm main' >> "$log" 2>&1
	add-apt-repository -y -S 'deb http://deb.freepbx.org/freepbx17-prod bookworm main' >> "$log" 2>&1
fi

# Updating the new repo
apt update >> $log 2>&1

# log the apt-cache policy 
apt-cache policy  >> $log 2>&1

#chown -R asterisk:asterisk /etc/ssl

# Install Asterisk
if [ $noast ] ; then
	message "Skipping Asterisk RPM installation due to noastrisk option"
else 
	# TODO Need to check if asterisk installed already then remove that and install new ones.
	# Install Asterisk 21
	install_asterisk $ASTVERSION
fi

message "Installing FreePBX dependent packages"
# Install PBX dependent RPMs
pkg_install ioncube-loader-82
pkg_install sysadmin17
pkg_install sangoma-pbx17
pkg_install ffmpeg
#Enabling freepbx.ini file
/usr/sbin/phpenmod freepbx
mkdir -p /var/lib/php/session

#Creating default config files
touch /etc/asterisk/extconfig_custom.conf
touch /etc/asterisk/extensions_override_freepbx.conf
touch /etc/asterisk/extensions_additional.conf
touch /etc/asterisk/extensions_custom.conf
chown -R asterisk:asterisk /etc/asterisk


log "Restarting fail2ban "
/usr/bin/systemctl restart fail2ban  >> $log

message "###### STEP-3 END ######################### "
#
#
########################################################################################
# Step-4 : Install FreePBX
########################################################################################
log "############################### "
message "###### STEP-4 Installing FreePBX BEGIN ######################### "

if [ $nofpbx ] ; then
	message "Skipping FreePBX 17 fresh tarball installation due to nofreepbx option"
else 
	pkg_install freepbx17 
fi

# Reinstalling modules to ensure all the modules are enabled/installed
fwconsole ma install sysadmin >> $log 2>&1
message "Installing FreePBX 17 modules.."
fwconsole ma installlocal >> $log 2>&1 
message "Upgrading FreePBX 17 modules.."
fwconsole ma upgradeall >> $log 2>&1 
message "Executing fwconsole reload/restart .."
fwconsole reload >> $log 2>&1 
fwconsole restart >> $log 2>&1 

message "###### STEP-4 END ######################### "
########################################################################################
# Final system wrapup
#
########################################################################################
message "Wrapping up the installation process.."
systemctl daemon-reload >> "$log" 2>&1
systemctl enable freepbx >> "$log" 2>&1

#delete apache2 index.html as we do not need that file
rm -f /var/www/html/index.html  

#enable apache mod ssl
/usr/sbin/a2enmod ssl  >> "$log" 2>&1

#enable apache mod expires
/usr/sbin/a2enmod expires  >> "$log" 2>&1

#enable apache 
a2enmod rewrite >> "$log" 2>&1

#Enabling freepbx apache configuration
cd /etc/apache2/sites-enabled/ && ln -s ../sites-available/freepbx.conf freepbx.conf >> "$log" 2>&1

#Setting postfix size to 100MB
/usr/sbin/postconf -e message_size_limit=102400000

# Restart apache2
systemctl restart apache2 >> "$log" 2>&1

# Refresh signatures 
/usr/sbin/fwconsole ma refreshsignatures >> "$log" 2>&1

#Do not want to upgrade initial(first time setup) packages
apt-mark hold freepbx17
apt-mark hold sangoma-pbx17

############ TODO - POST INSTALL VALIDATION ############################################
########################################################################################
duration=$(echo "$(date +%s.%N) - $start" | bc)
execution_time=`printf "%.2f seconds" $duration`
message "Total script Execution Time: $execution_time"
message "Finished FreePBX 17 installation process for $host $kernel"
message "Join us on the FreePBX Community Forum: https://community.freepbx.org/ ";
########################################################################################
/usr/sbin/fwconsole motd
########################################################################################
terminate
########################################################################################
