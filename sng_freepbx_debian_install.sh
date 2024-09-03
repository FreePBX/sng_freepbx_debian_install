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
set -e
SCRIPTVER="1.10"
ASTVERSION=21
PHPVERSION="8.2"
LOG_FOLDER="/var/log/pbx"
LOG_FILE="${LOG_FOLDER}/freepbx17-install-$(date '+%Y.%m.%d-%H.%M.%S').log"
log=$LOG_FILE
SANE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Setup a sane PATH for script execution as root
if ! grep -q "export PATH=$SANE_PATH" /root/.bashrc; then
  echo "export PATH=$SANE_PATH" >> /root/.bashrc
  export PATH=$SANE_PATH
fi

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
		--opensourceonly)
			opensourceonly=true
			shift # past argument
			;;
		--noioncube)
			noioncube=true
			shift # past argument
			;;
		--noaac)
			noaac=true
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
		--dahdi-only)
			nofpbx=true
			noast=true
			noioncube=true
			noaac=true
			dahdi=true
			shift # past argument
			;;
		-*)
			echo "Unknown option $1"
			exit 1
			;;
		*)
			echo "Unknown argument \"$1\""
			exit 1
			;;
	esac
done

mkdir -p "${LOG_FOLDER}"
echo "" > $log

#Helpers APIs
exec 2>>${LOG_FILE}

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
	PKG_OK=$(dpkg-query -W --showformat='${Status}\n' "$@" 2>/dev/null|grep "install ok installed")
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
	apt-key del "9641 7C6E 0423 6E0A 986B  69EF DE82 7447 3C8D 0E52" >> "$log" 2>&1

	wget -qO - http://deb.freepbx.org/gpg/aptly-pubkey.asc | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/freepbx.gpg  >> "$log" 2>&1

	# Setting our default repo server
	if [ $testrepo ] ; then
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-dev bookworm main" >> "$log" 2>&1
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-dev bookworm main" >> "$log" 2>&1
	else
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-prod bookworm main" >> "$log" 2>&1
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-prod bookworm main" >> "$log" 2>&1
	fi

	if [ ! $noaac ] ; then
		add-apt-repository -y -S "deb http://ftp.debian.org/debian/ stable main non-free non-free-firmware" >> "$log" 2>&1
	fi

	setCurrentStep "Setting up Sangoma repository"
    local aptpref="/etc/apt/preferences.d/99sangoma-fpbx-repository"
    cat <<EOF> $aptpref
Package: *
Pin: origin deb.freepbx.org
Pin-Priority: ${MIRROR_PRIO}
EOF
    if [ $noaac ]; then
    cat <<EOF>> $aptpref

Package: ffmpeg
Pin: origin deb.freepbx.org
Pin-Priority: 1
EOF
    fi
}

#create post apt run script to run and check everything apt command is finished executing
create_post_apt_script() {
    #checking post-apt-run script
    if [ -e "/usr/bin/post-apt-run" ]; then
        rm -f /usr/bin/post-apt-run
    fi

    message "Creating script to run post every apt command is finished executing"
    {
        echo "#!/bin/bash"
        echo ""
        echo "kernel_idx=\$(grep GRUB_DEFAULT /etc/default/grub | cut -d '=' -f 2)"
        echo "kernel_pres=\$(sed -n '/^menuentry/,/}/p' /boot/grub/grub.cfg  | grep -o -P 'vmlinuz-\S+')"
        echo ""
        echo "dahdi_pres=\$(dpkg -l | grep dahdi-linux | wc -l)"
        echo ""
        echo "if [[ \$dahdi_pres -gt 0 ]]; then"
        echo "    idx=0"
        echo "    for kernel in \$kernel_pres; do"
        echo "        if [[ \$idx -ne \$kernel_idx ]]; then"
        echo "            idx=\$((idx+1))"
        echo "            continue"
        echo "        fi"
        echo ""
        echo "        kernel_ver=\$(echo \$kernel | sed -n -e 's/vmlinuz-\([[:digit:].-]*\).*/\\1/' -e 's/-$//p')"
        echo "        logger \"Checking kernel modules for dahdi and wanpipe for kernel image \$kernel_ver\""
        echo ""
        echo "        #check if dahdi is installed or not of respective kernel version"
        echo "        dahdi_kmod_pres=\$(dpkg -l | grep dahdi-linux-kmod | grep \$kernel_ver | wc -l)"
        echo "        wanpipe_kmod_pres=\$(dpkg -l | grep kmod-wanpipe | grep \$kernel_ver | wc -l)"
        echo ""
        echo "        if [[ \$dahdi_kmod_pres -eq 0 ]] && [[ \$wanpipe_kmod_pres -eq 0 ]]; then"
        echo "            logger \"Upgrading dahdi-linux-kmod-\$kernel_ver and kmod-wanpipe-\$kernel_ver\""
        echo "            echo \"Please wait for approx 2 min once apt command execution is completed as dahdi-linux-kmod-\$kernel_ver kmod-wanpipe-\$kernel_ver update in progress\""
        echo "            apt -y upgrade dahdi-linux-kmod-\$kernel_ver kmod-wanpipe-\$kernel_ver > /dev/null 2>&1 | at now +1 minute&"
        echo "        elif [[ \$dahdi_kmod_pres -eq 0 ]]; then"
        echo "            logger \"Upgrading dahdi-linux-kmod-\$kernel_ver\""
        echo "            echo \"Please wait for approx 2 min once apt command execution is completed as dahdi-linux-kmod-\$kernel_ver update in progress\""
        echo "            apt -y upgrade dahdi-linux-kmod-\$kernel_ver > /dev/null 2>&1 | at now +1 minute&"
        echo "        elif [[ \$wanpipe_kmod_pres -eq 0 ]];then"
        echo "            logger \"Upgrading kmod-wanpipe-\$kernel_ver\""
        echo "            echo \"Please wait for approx 2 min once apt command execution is completed as kmod-wanpipe-\$kernel_ver update in progress\""
        echo "            apt -y upgrade kmod-wanpipe-\$kernel_ver > /dev/null 2>&1 | at now +1 minute&"
        echo "        fi"
        echo ""
        echo "        break"
        echo "    done"
        echo "else"
        echo "    logger \"Dahdi / wanpipe is not present therefore, not checking for dahdi / wanpipe kmod upgrade\""
        echo "fi"
        echo ""
        echo "if [ -e "/var/www/html/index.html" ]; then"
        echo "    rm -f /var/www/html/index.html"
        echo "fi"
    } >> /usr/bin/post-apt-run

    #Changing file permission to run script
    chmod 755 /usr/bin/post-apt-run

    #Adding Post Invoke for Update to run kernel-check
    if [ -e "/etc/apt/apt.conf.d/80postaptcmd" ]; then
        rm -f /etc/apt/apt.conf.d/80postaptcmd
    fi

    echo "DPkg::Post-Invoke {\"/usr/bin/post-apt-run\";};" >> /etc/apt/apt.conf.d/80postaptcmd
    chmod 644 /etc/apt/apt.conf.d/80postaptcmd
}

check_kernel_compatibility() {
    local latest_dahdi_supported_version=$(apt-cache search dahdi | grep -E "^dahdi-linux-kmod-[0-9]" | awk '{print $1}' | awk -F'-' '{print $4"-"$5}' | sort -n | tail -1)
    local latest_wanpipe_supported_version=$(apt-cache search wanpipe | grep -E "^kmod-wanpipe-[0-9]" | awk '{print $1}' | awk -F'-' '{print $3"-"$4}' | sort -n | tail -1)
    local curr_kernel_version=$(apt-cache show linux-headers-$(uname -r) | sed -n -e 's/Package: linux-headers-\\([[:digit:].-]*\\).*/\\1/' -e 's/-\$//p' | uniq)

    if dpkg --compare-versions "$latest_dahdi_supported_version" "eq" "$latest_wanpipe_supported_version"; then
        local supported_kernel_version=$latest_dahdi_supported_version
    else
        local supported_kernel_version="6.1.0.22"
    fi

    if dpkg --compare-versions "$curr_kernel_version" "gt" "$supported_kernel_version"; then
        message "Aborting freepbx installation as detected kernel version $curr_kernel_version is not supported by freepbx dahdi module $supported_kernel_version"
	exit
    fi

    if [ -e "/usr/bin/kernel-check" ]; then
        rm -f /usr/bin/kernel-check
    fi

    if [ $testrepo ]; then
        message "Skipping Kernel Check. As Kernel Check is not required for testing repo....."
        return
    fi

    message "Creating kernel check script to allow proper kernel upgrades"
    {
        echo "#!/bin/bash"
        echo ""
        echo "curr_kernel_version=\"\""
        echo "supported_kernel_version=\"\""
        echo ""

        echo "set_supported_kernel_version() {"
        echo "    local latest_dahdi_supported_version=\$(apt-cache search dahdi | grep -E \"^dahdi-linux-kmod-[0-9]\" | awk '{print \$1}' | awk -F'-' '{print \$4,-\$5}' | sed 's/[[:space:]]//g' | sort -n | tail -1)"
        echo "    local latest_wanpipe_supported_version=\$(apt-cache search wanpipe | grep -E \"^kmod-wanpipe-[0-9]\" | awk '{print \$1}' | awk -F'-' '{print \$3,-\$4}' | sed 's/[[:space:]]//g' | sort -n | tail -1)"
        echo "    curr_kernel_version=\`apt-cache show linux-headers-\$(uname -r) | sed -n -e 's/Package: linux-headers-\([[:digit:].-]*\).*/\1/' -e 's/-$//p' | uniq\`"
        echo ""
        echo "    if dpkg --compare-versions \"\$latest_dahdi_supported_version\" \"eq\" \"\$latest_wanpipe_supported_version\"; then"
        echo "        supported_kernel_version=\$latest_dahdi_supported_version"
        echo "    else"
        echo "        supported_kernel_version=\"6.1.0-21\""
        echo "    fi"
        echo "}"
        echo ""

        echo "check_and_unblock_kernel() {"
        echo "    local kernel_packages=\$(apt-mark showhold | grep -E ^linux-image-[0-9] | awk '{print \$1}')"
        echo ""
        echo "    if [[ \"w\$1\" != \"w\" ]]; then"
        echo "        # Compare the version with the current supported kernel version"
        echo "        if dpkg --compare-versions \"\$1\" \"le\" \"\$supported_kernel_version\"; then"
        echo "            local is_on_hold=\$(apt-mark showhold | grep -E ^linux-image-[0-9] | awk '{print \$1}' | grep -w \"\$1\" | wc -l )"
        echo ""
        echo "            if [[ \$is_on_hold -gt 0 ]]; then"
        echo "                logger \"Un-Holding kernel version \$version to allow automatic updates.\""
        echo "                apt-mark unhold \"\$version\" >> /dev/null 2>&1"
        echo "            fi"
        echo "        fi"
        echo "        return"
        echo "    fi"
        echo ""
        echo "    for package in \$kernel_packages; do"
        echo "        # Extract the version from the package name"
        echo "        local version=\$(echo \"\$package\" | awk -F'-' '{print \$3,-\$4}' | sed 's/[[:space:]]//g' | sort -n)"
        echo ""
        echo "        # Compare the version with the current supported kernel version"
        echo "        if dpkg --compare-versions \"\$version\" \"le\" \"\$supported_kernel_version\"; then"
        echo "            logger \"Un-Holding kernel version \$version to allow automatic updates.\""
        echo "            apt-mark unhold \"\$version\" >> /dev/null 2>&1"
        echo "        fi"
        echo "    done"
        echo "}"

        echo ""
        echo "check_and_block_kernel() {"
        echo "    if dpkg --compare-versions \"\$curr_kernel_version\" \"gt\" \"\$supported_kernel_version\"; then"
        echo "        logger \"Aborting as detected kernel version is not supported by freepbx dahdi module\""
        echo "    fi"
        echo ""

        echo "    local kernel_packages=\$( apt-cache search linux-image | grep -E "^linux-image-[0-9]" | awk '{print \$1}')"
        echo "    for package in \$kernel_packages; do"
        echo "        # Extract the version from the package name"
        echo "        local version=\$(echo \"\$package\" | awk -F'-' '{print \$3,-\$4}' | sed 's/[[:space:]]//g' | sort -n)"
        echo ""

        echo "        # Compare the version with the current supported kernel version"
        echo "        if dpkg --compare-versions \"\$version\" \"gt\" \"\$supported_kernel_version\"; then"
        echo "            logger \"Holding kernel version \$version to prevent automatic updates.\""
        echo "            apt-mark hold \"\$version\" >> /dev/null 2>&1"
        echo "        else"
        echo "            check_and_unblock_kernel \$version"
        echo "        fi"
        echo "    done"
        echo "}"

        echo ""
        echo "case \$1 in"
        echo "    --hold)"
        echo "        hold=true"
        echo "        ;;"
        echo ""
        echo "    --unhold)"
        echo "        unhold=true"
        echo "        ;;"
        echo ""
        echo "    *)"
        echo "        logger \"Unknown / Invalid option \$1\""
        echo "        exit 1"
        echo "        ;;"
        echo "esac"
        echo ""
        echo "set_supported_kernel_version"
        echo ""
        echo "if [[ \$hold ]]; then"
        echo "    check_and_block_kernel"
        echo "elif [[ \$unhold ]]; then"
        echo "    check_and_unblock_kernel"
        echo "fi"
    } >> /usr/bin/kernel-check

    #Changing file permission to run script
    chmod 755 /usr/bin/kernel-check

    #Adding Post Invoke for Update to run kernel-check
    if [ -e "/etc/apt/apt.conf.d/05checkkernel" ]; then
        rm -f /etc/apt/apt.conf.d/05checkkernel
    fi
    echo "APT::Update::Post-Invoke {\"/usr/bin/kernel-check --hold\"}" >> /etc/apt/apt.conf.d/05checkkernel
    chmod 644 /etc/apt/apt.conf.d/05checkkernel
}

remove_commercial_modules() {
  comm_modules=$(fwconsole ma list | grep Commercial | awk '{print $2}')
  echo "$comm_modules" | xargs -I {} fwconsole ma -f uninstall {} >> "$log" 2>&1
  echo "$comm_modules" | xargs -I {} fwconsole ma remove {} >> "$log" 2>&1
  # Remove firewall module also because it depends on commercial sysadmin module
  fwconsole ma uninstall firewall >> "$log" 2>&1
  fwconsole ma remove firewall >> "$log" 2>&1
}

refresh_signatures() {
  fwconsole ma refreshsignatures >> "$log" 2>&1
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

    # Checking whether enabled PHP modules are of PHP 8.2 version
    php_module_version=$(a2query -m | grep php | awk '{print $1}')

    if [[ "$php_module_version" == "php8.2" ]]; then
       log "The PHP module version $php_module_version is compatible with FreePBX. Proceeding with the script."
    else
       log "The installed PHP module version $php_module_version is not compatible with FreePBX. Please install PHP version '8.2'."
       exit 1
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
	if [ ! $opensourceonly ] ; then
        	inspect_network_ports
	fi
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

hold_packages() {
    if [ ! $nofpbx ] ; then
      apt-mark hold freepbx17
    fi
    # List of package names to hold
    local packages=("sangoma-pbx17" "nodejs" "node-*")

    # Loop through each package and hold it
    for pkg in "${packages[@]}"; do
        apt-mark hold "$pkg"
    done
}

################################################################################################################
MIRROR_PRIO=600
kernel=$(uname -a)
host=$(hostname)
fqdn="$(hostname -f)" || true

# Install wget which is required for version check
pkg_install wget

# Script version check
if [[ $skipversion ]]; then
    message "Skipping version check..."
else
    # Perform version check if --skipversion is not provided
    message "Performing version check..."
    check_version
fi

# Check if we are running on a 64-bit system
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" != "amd64" ]; then
    message "FreePBX 17 installation can only be made on a 64-bit (amd64) system!"
    message "Current System's Architecture: $ARCH"
    exit 1
fi

# Check if hostname command succeeded and FQDN is not empty
if [ -z "$fqdn" ]; then
    echo "Fully qualified domain name (FQDN) is not set correctly."
    echo "Please set the FQDN for this system and re-run the script."
    echo "To set the FQDN, update the /etc/hostname and /etc/hosts files."
    exit 1
fi

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

setCurrentStep "Making sure installation is sane"
# Fixing broken install
apt-get -y --fix-broken install >> $log 2>&1
apt-get autoremove -y >> "$log" 2>&1

# Check if the CD-ROM repository is present in the sources.list file
if grep -q "^deb cdrom" /etc/apt/sources.list; then
  # Comment out the CD-ROM repository line in the sources.list file
  sed -i '/^deb cdrom/s/^/#/' /etc/apt/sources.list
  message "Commented out CD-ROM repository in sources.list"
fi

apt-get update >> $log 2>&1

# Adding iptables and postfix  inputs so "iptables-persistent" and postfix will not ask for the input
setCurrentStep "Setting up default configuration"
debconf-set-selections <<EOF
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
EOF
echo "postfix postfix/mailname string ${fqdn}" | debconf-set-selections
echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections

# Install below packages which are required for repositories setup
pkg_install software-properties-common
pkg_install gnupg

setCurrentStep "Setting up repositories"
setup_repositories

lat_dahdi_supp_ver=$(apt-cache search dahdi | grep -E "^dahdi-linux-kmod-[0-9]" | awk '{print $1}' | awk -F'-' '{print $4"-"$5}' | sort -n | tail -1)
curr_ker_ver=$(apt-cache show linux-headers-$(uname -r) | sed -n -e 's/Package: linux-headers-\\([[:digit:].-]*\\).*/\\1/' -e 's/-\$//p' | uniq)

message " You are installing FreePBX 17 on kernel $curr_ker_ver.."
message " Please note that if you have plan to use DAHDI then:"
message " Ensure that you either choose DAHDI option so script will configure DAHDI"
message "                                  OR"
message " Ensure you are always running DAHDI supported Kernel. Current DAHDI supporter latest kernel version is $lat_dahdi_supp_ver"

if [ $dahdi ]; then
    setCurrentStep "Making sure we allow only proper kernel upgrade and version installation"
    check_kernel_compatibility
fi

setCurrentStep "Updating repository"
apt-get update >> $log 2>&1

# log the apt-cache policy
apt-cache policy  >> $log 2>&1

# Don't start the tftp & chrony daemons automatically, as we need to change their configuration
systemctl mask tftpd-hpa.service chrony.service

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
	"php${PHPVERSION}-soap"
	"php${PHPVERSION}-ssh2"
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
 	"python3-mysqldb"
 	"default-libmysqlclient-dev"
 	"at"
)
for i in "${!DEPPKGS[@]}"; do
	pkg_install ${DEPPKGS[$i]}
done

if  dpkg -l | grep -q 'postfix'; then
    warning_message="# WARNING: Changing the inet_interfaces to an IP other than 127.0.0.1 may expose Postfix to external network connections.\n# Only modify this setting if you understand the implications and have specific network requirements."

    if ! grep -q "WARNING: Changing the inet_interfaces" /etc/postfix/main.cf; then
        # Add the warning message above the inet_interfaces configuration
        sed -i "/^inet_interfaces\s*=/i $warning_message" /etc/postfix/main.cf
    fi

    sed -i "s/^inet_interfaces\s*=.*/inet_interfaces = 127.0.0.1/" /etc/postfix/main.cf

    systemctl restart postfix
fi

# OpenVPN EasyRSA configuration
if [ ! -d "/etc/openvpn/easyrsa3" ]; then
	make-cadir /etc/openvpn/easyrsa3
fi
#Remove below files which will be generated by sysadmin later
rm -f /etc/openvpn/easyrsa3/pki/vars || true
rm -f /etc/openvpn/easyrsa3/vars

# Install Dahdi card support if --dahdi option is provided
if [[ "$dahdi" == true ]]; then
    echo "Installing Dahdi card support..."
    kernel_version=$(apt-cache show linux-headers-$(uname -r) | sed -n -e 's/Package: linux-headers-\\([[:digit:].-]*\\).*/\\1/' -e 's/-\$//p' | uniq)
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

# Install libfdk-aac2
if [ $noaac ] ; then
	message "Skipping libfdk-aac2 installation due to noaac option"
else
	pkg_install libfdk-aac2
fi

setCurrentStep "Removing unnecessary packages"
apt-get autoremove -y >> "$log" 2>&1

execution_time="$(($(date +%s) - start))"
message "Execution time to install all the dependent packages : $execution_time s"




setCurrentStep "Setting up folders and asterisk config"
groupExists="$(getent group asterisk || echo '')"
if [ "${groupExists}" = "" ]; then
	groupadd -r asterisk
fi

userExists="$(getent passwd asterisk || echo '')"
if [ "${userExists}" = "" ]; then
	useradd -r -g asterisk -d /home/asterisk -M -s /bin/bash asterisk
fi

# Adding asterisk to the sudoers list
#echo "%asterisk ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers

# Creating /tftpboot directory
mkdir -p /tftpboot
chown -R asterisk:asterisk /tftpboot
# Changing the tftp process path to tftpboot
sed -i -e "s|^TFTP_DIRECTORY=\"/srv\/tftp\"$|TFTP_DIRECTORY=\"/tftpboot\"|" /etc/default/tftpd-hpa
# Change the tftp & chrony options when IPv6 is not available, to allow successful execution
if [ ! -f /proc/net/if_inet6 ]; then
	sed -i -e "s|^TFTP_OPTIONS=\"--secure\"$|TFTP_OPTIONS=\"--secure --ipv4\"|" /etc/default/tftpd-hpa
	sed -i -e "s|^DAEMON_OPTS=\"-F 1\"$|DAEMON_OPTS=\"-F 1 -4\"|" /etc/default/chrony
fi
# Start the tftp & chrony daemons
systemctl unmask tftpd-hpa.service chrony.service
systemctl start tftpd-hpa.service chrony.service

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

#Setting higher precedence value to IPv4
sed -i 's/^#\s*precedence ::ffff:0:0\/96  100/precedence ::ffff:0:0\/96  100/' /etc/gai.conf

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
	VIMRUNTIME=$(vim -e -T dumb --cmd 'exe "set t_cm=\<C-M>"|echo $VIMRUNTIME|quit' | tr -d '\015' )
	VIMRUNTIME_FOLDER=$(echo $VIMRUNTIME | sed 's/ //g')

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


# Setting apt configuration to always DO NOT overwrite existing configurations
cat <<EOF >> /etc/apt/apt.conf.d/00freepbx
DPkg::options { "--force-confdef"; "--force-confold"; }
EOF


#chown -R asterisk:asterisk /etc/ssl

# Install Asterisk
if [ $noast ] ; then
	message "Skipping Asterisk installation due to noasterisk option"
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
phpenmod freepbx
mkdir -p /var/lib/php/session

#Creating default config files
mkdir -p /etc/asterisk
touch /etc/asterisk/extconfig_custom.conf
touch /etc/asterisk/extensions_override_freepbx.conf
touch /etc/asterisk/extensions_additional.conf
touch /etc/asterisk/extensions_custom.conf
chown -R asterisk:asterisk /etc/asterisk

setCurrentStep "Restarting fail2ban"
systemctl restart fail2ban  >> $log


if [ $nofpbx ] ; then
	message "Skipping FreePBX 17 fresh tarball installation due to nofreepbx option"
else
	setCurrentStep "Installing FreePBX 17"
	pkg_install freepbx17

	# Reinstalling modules to ensure all the modules are enabled/installed
  setCurrentStep "Installing Sysadmin module"
  fwconsole ma install sysadmin >> $log 2>&1

  #Not installing sangoma connect result in failure of first installlocal
  setCurrentStep "Installing sangomaconnect module"
  fwconsole ma install sangomaconnect>> $log 2>&1


  if [ $dahdi ]; then
	fwconsole ma downloadinstall dahdiconfig
	echo 'export PERL5LIB=$PERL5LIB:/etc/wanpipe/wancfg_zaptel' | sudo tee -a /root/.bashrc
  fi

  setCurrentStep "Installing all local modules"
  fwconsole ma installlocal >> $log 2>&1

  # Check if only opensource required then remove the commercial modules
  if [ $opensourceonly ] ; then
	setCurrentStep "Removing commercial modules"
	remove_commercial_modules
  fi

  setCurrentStep "Upgrading FreePBX 17 modules"
  fwconsole ma upgradeall >> $log 2>&1

  setCurrentStep "Reloading and restarting FreePBX 17"
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
a2enmod ssl  >> "$log" 2>&1

#enable apache mod expires
a2enmod expires  >> "$log" 2>&1

#enable apache
a2enmod rewrite >> "$log" 2>&1

#Enabling freepbx apache configuration
if [ ! $nofpbx ] ; then 
  a2ensite freepbx.conf >> "$log" 2>&1
fi

#Setting postfix size to 100MB
postconf -e message_size_limit=102400000

# Disable expose_php for provide less information to attacker
sed -i 's/\(^expose_php = \).*/\1Off/' /etc/php/${PHPVERSION}/apache2/php.ini

# Disable ServerTokens and ServerSignature for provide less information to attacker
sed -i 's/\(^ServerTokens \).*/\1Prod/' /etc/apache2/conf-available/security.conf
sed -i 's/\(^ServerSignature \).*/\1Off/' /etc/apache2/conf-available/security.conf

# Make sure that the apache service start after freepbx service is started
if [ -e "/lib/systemd/system/apache2.service" ]; then
    if [ -e "/lib/systemd/system/freepbx.service" ]; then
        is_fpbx_pres=$(grep -nr "freepbx.service" /lib/systemd/system/apache2.service | wc -l)

        if [ $is_fpbx_pres -eq 0 ]; then
            sed -i '/After=/s/$/ freepbx.service/' /lib/systemd/system/apache2.service
        fi
    fi
fi


# Restart apache2
systemctl restart apache2 >> "$log" 2>&1

# Refresh signatures
count=1
if [ ! $nofpbx ]; then
  while [ $count -eq 1 ]; do
    set +e
    refresh_signatures
    exit_status=$?
    set -e
    if [ $exit_status -eq 0 ]; then
      break
    else
      log "Command 'fwconsole ma refreshsignatures' failed to execute with exit status $exit_status, running as a background job"
      refresh_signatures &
      log "Continuing the remaining script execution"
      break
    fi
  done
fi

setCurrentStep "Holding Packages"

hold_packages

# Update logrotate configuration
if grep -q '^#dateext' /etc/logrotate.conf; then
   message "Setting up logrotate.conf"
   sed -i 's/^#dateext/dateext/' /etc/logrotate.conf
fi

#setting permisions
chown -R asterisk:asterisk /var/www/html/

#Creating post apt scripts
create_post_apt_script

setCurrentStep "FreePBX 17 Installation finished successfully."


############ POST INSTALL VALIDATION ############################################
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

execution_time="$(($(date +%s) - start))"
message "Total script Execution Time: $execution_time"
message "Finished FreePBX 17 installation process for $host $kernel"
message "Join us on the FreePBX Community Forum: https://community.freepbx.org/ ";

if [ ! $nofpbx ] ; then
  fwconsole motd
fi
