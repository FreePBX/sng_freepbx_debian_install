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
SCRIPTVER="1.14"
ASTVERSION=22
PHPVERSION="8.2"
LOG_FOLDER="/var/log/pbx"
LOG_FILE="${LOG_FOLDER}/freepbx17-install-$(date '+%Y.%m.%d-%H.%M.%S').log"
log=$LOG_FILE
SANE_PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DEBIAN_MIRROR="http://ftp.debian.org/debian"
NPM_MIRROR=""

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi


# Setup a sane PATH for script execution as root
export PATH=$SANE_PATH

while [[ $# -gt 0 ]]; do
	case $1 in
		--dev)
			dev=true
			shift # past argument
			;;
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
			noaac=true
			dahdi=true
			shift # past argument
			;;
		--nochrony)
			nochrony=true
			shift # past argument
			;;
		--debianmirror)
			DEBIAN_MIRROR=$2
			shift; shift # past argument
			;;
    --npmmirror)
      NPM_MIRROR=$2
      shift; shift # past argument
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

# Create the log file
mkdir -p "${LOG_FOLDER}"
touch "${LOG_FILE}"

# Redirect stderr to the log file
exec 2>>"${LOG_FILE}"

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
    wget -O /tmp/sng_freepbx_debian_install_latest_from_github.sh "$REPO_URL/sng_freepbx_debian_install.sh" >> "$log"

    latest_version=$(grep '^SCRIPTVER="' /tmp/sng_freepbx_debian_install_latest_from_github.sh | awk -F'"' '{print $2}')
    latest_checksum=$(sha256sum /tmp/sng_freepbx_debian_install_latest_from_github.sh | awk '{print $1}')

    # Cleaning up downloaded file
    rm -f /tmp/sng_freepbx_debian_install_latest_from_github.sh

    compare_version $SCRIPTVER "$latest_version"

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
    PKG=("$@")  # Assign arguments as an array
    if isinstalled "${PKG[@]}"; then
        log "${PKG[*]} already present ...."   # Use * to join the array into a string
    else
        message "Installing ${PKG[*]} ...."
        apt-get -y --ignore-missing -o DPkg::Options::="--force-confnew" -o Dpkg::Options::="--force-overwrite" install "${PKG[@]}" >> "$log"
        if isinstalled "${PKG[@]}"; then
            message "${PKG[*]} installed successfully...."
        else
            message "${PKG[*]} failed to install ...."
            message "Exiting the installation process as dependent ${PKG[*]} failed to install ...."
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
	pkg_install asterisk"$astver"

	for i in "${!ASTPKGS[@]}"; do
		pkg_install asterisk"$astver"-"${ASTPKGS[$i]}"
	done

	pkg_install asterisk"$astver".0-freepbx-asterisk-modules
	pkg_install asterisk-version-switch
	pkg_install asterisk-sounds-*
}

setup_repositories() {
	apt-key del "9641 7C6E 0423 6E0A 986B  69EF DE82 7447 3C8D 0E52" >> "$log"

	wget -O - http://deb.freepbx.org/gpg/aptly-pubkey.asc | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/freepbx.gpg  >> "$log"

	# Setting our default repo server
	if [ "$testrepo" ] ; then
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-dev bookworm main" >> "$log"
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-dev bookworm main" >> "$log"
	else
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-prod bookworm main" >> "$log"
		add-apt-repository -y -S "deb [ arch=amd64 ] http://deb.freepbx.org/freepbx17-prod bookworm main" >> "$log"
	fi

	if [ ! "$noaac" ] ; then
		add-apt-repository -y -S "deb $DEBIAN_MIRROR stable main non-free non-free-firmware" >> "$log"
	fi

	setCurrentStep "Setting up Sangoma repository"
    local aptpref="/etc/apt/preferences.d/99sangoma-fpbx-repository"
    cat <<EOF> $aptpref
Package: *
Pin: origin deb.freepbx.org
Pin-Priority: ${MIRROR_PRIO}
EOF
    if [ "$noaac" ]; then
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
        echo "if pidof -x 'asterisk-version-switch' > /dev/null; then"
	echo "echo \"Asterisk version switch process is running, skipping post-apt script.\""
	echo "exit 0"
	echo "fi"
	echo ""
        echo "dahdi_pres=\$(dpkg -l | grep dahdi-linux | wc -l)"
        echo ""
        echo "if [[ \$dahdi_pres -gt 0 ]]; then"
	echo "    kernel_idx=\$(grep -v '^#' /etc/default/grub | grep GRUB_DEFAULT | cut -d '=' -f2 | tr -d '\"')"
	echo ""
	echo "    # Check if it contains '>'"
	echo "    if [[ \"\$kernel_idx\" == *\">\"* ]]; then"
	echo "        # Extract the value after '>'"
	echo "        selected_idx=\"\${kernel_idx#*>}\""
	echo "        submenu_format=true"
	echo "    else"
	echo "        # It's a numeric index, use it directly"
	echo "        selected_idx=\"\$kernel_idx\""
	echo "        submenu_format=false"
	echo "    fi"
	echo ""
	echo "    kernel_pres=\$(grep -oP \"menuentry '.*?Linux \K[0-9.-]+(?=-amd64)\" /boot/grub/grub.cfg)"
	echo "    kernel_count=\$(echo \"\$kernel_pres\" | wc -l)"
	echo ""
	echo "    if [[ \"\$selected_idx\" -ge \"\$kernel_count\" ]]; then"
	echo "        if \$submenu_format; then"
	echo "            echo \"ERROR: GRUB_DEFAULT is set to '\$kernel_idx' (submenu index: \$selected_idx), but only \$kernel_count kernel entries are available.\""
	echo "            echo \"       This likely refers to a non-existent kernel inside a submenu (e.g., 'Advanced options for Debian GNU/Linux').\""
        echo "            echo \"       Please update /etc/default/grub to a valid submenu index between 0 and \$((kernel_count - 1)), then run: update-grub\""
	echo "        else"
	echo "            echo \"ERROR: GRUB_DEFAULT is set to '\$selected_idx', but only \$kernel_count kernel entries were found.\""
	echo "            echo \"       Valid indices are between 0 and \$((kernel_count - 1)).\""
	echo "            echo \"       Please update /etc/default/grub and run: update-grub\""
	echo "        fi"
	echo "        exit 1"
	echo "    fi"
	echo ""
	echo "    idx=0"
        echo "    for kernel in \$kernel_pres; do"
        echo "        if [[ \$idx -ne \$selected_idx ]]; then"
        echo "            idx=\$((idx+1))"
        echo "            continue"
        echo "        fi"
        echo ""
        echo "        logger \"Checking kernel modules for dahdi and wanpipe for kernel image \$kernel\""
        echo ""
        echo "        #check if dahdi is installed or not of respective kernel version"
        echo "        dahdi_kmod_pres=\$(dpkg -l | grep dahdi-linux-kmod | grep \$kernel | wc -l)"
        echo "        wanpipe_kmod_pres=\$(dpkg -l | grep kmod-wanpipe | grep \$kernel | wc -l)"
        echo ""
        echo "        if [[ \$dahdi_kmod_pres -eq 0 ]] && [[ \$wanpipe_kmod_pres -eq 0 ]]; then"
        echo "            logger \"Upgrading dahdi-linux-kmod-\$kernel and kmod-wanpipe-\$kernel\""
        echo "            echo \"Please wait for approx 2 min once apt command execution is completed as dahdi-linux-kmod-\$kernel kmod-wanpipe-\$kernel update in progress\""
        echo "            apt -y upgrade dahdi-linux-kmod-\$kernel kmod-wanpipe-\$kernel > /dev/null 2>&1 | at now +1 minute&"
        echo "        elif [[ \$dahdi_kmod_pres -eq 0 ]]; then"
        echo "            logger \"Upgrading dahdi-linux-kmod-\$kernel\""
        echo "            echo \"Please wait for approx 2 min once apt command execution is completed as dahdi-linux-kmod-\$kernel update in progress\""
        echo "            apt -y upgrade dahdi-linux-kmod-\$kernel > /dev/null 2>&1 | at now +1 minute&"
        echo "        elif [[ \$wanpipe_kmod_pres -eq 0 ]];then"
        echo "            logger \"Upgrading kmod-wanpipe-\$kernel\""
        echo "            echo \"Please wait for approx 2 min once apt command execution is completed as kmod-wanpipe-\$kernel update in progress\""
        echo "            apt -y upgrade kmod-wanpipe-\$kernel > /dev/null 2>&1 | at now +1 minute&"
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
    local curr_kernel_version=$1

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

    if [ "$testrepo" ]; then
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
        echo "    curr_kernel_version=\$(uname -r | cut -d'-' -f1-2)"
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

refresh_signatures() {
  fwconsole ma refreshsignatures >> "$log"
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
	if [ ! "$opensourceonly" ] ; then
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
    # List of package names to hold
    local packages=("sangoma-pbx17" "nodejs" "node-*")
    if [ ! "$nofpbx" ] ; then
        packages+=("freepbx17")
    fi

    # Loop through each package and hold it
    for pkg in "${packages[@]}"; do
        apt-mark hold "$pkg" >> "$log"
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

# Check if running in a Container
if systemd-detect-virt --container &> /dev/null; then
	message "Running in a Container. Skipping Chrony installation."
	nochrony=true
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
pidfile='/var/run/freepbx17_installer.pid'

if [ -f "$pidfile" ]; then
	old_pid=$(cat "$pidfile")
	if ps -p "$old_pid" > /dev/null; then
		message "FreePBX 17 installation process is already going on (PID=$old_pid), hence not starting new process"
		exit 1
	else
		log "Removing stale PID file"
		rm -f "${pidfile}"
	fi
fi
echo "$$" > "$pidfile"

setCurrentStep "Starting installation."
trap 'errorHandler "$LINENO" "$?" "$BASH_COMMAND"' ERR
trap "terminate" EXIT

start=$(date +%s)
message "  Starting FreePBX 17 installation process for $host $kernel"
message "  Please refer to the $log to know the process..."
log "  Executing script v$SCRIPTVER ..."

setCurrentStep "Making sure installation is sane"
# Fixing broken install
apt-get -y --fix-broken install >> "$log"
apt-get autoremove -y >> "$log"

# Check if the CD-ROM repository is present in the sources.list file
if grep -q "^deb cdrom" /etc/apt/sources.list; then
  # Comment out the CD-ROM repository line in the sources.list file
  sed -i '/^deb cdrom/s/^/#/' /etc/apt/sources.list
  message "Commented out CD-ROM repository in sources.list"
fi

apt-get update >> "$log"

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
kernel_version=$(uname -r | cut -d'-' -f1-2)

message " You are installing FreePBX 17 on kernel $kernel_version."
message " Please note that if you have plan to use DAHDI then:"
message " Ensure that you either choose DAHDI option so script will configure DAHDI"
message "                                  OR"
message " Ensure you are running a DAHDI supported Kernel. Current latest supported kernel version is $lat_dahdi_supp_ver."

if [ "$dahdi" ]; then
    setCurrentStep "Making sure we allow only proper kernel upgrade and version installation"
    check_kernel_compatibility "$kernel_version"
fi

setCurrentStep "Updating repository"
apt-get update >> "$log"

# log the apt-cache policy
apt-cache policy  >> "$log"

# Don't start the tftp & chrony daemons automatically, as we need to change their configuration
systemctl mask tftpd-hpa.service
if [ "$nochrony" != true ]; then
	systemctl mask chrony.service
fi

# Install dependent packages
setCurrentStep "Installing required packages"
DEPPRODPKGS=(
	"redis-server"
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
	"wget"
	"vim"
	"openssh-server"
	"rsync"
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
	"mpg123"
	"sqlite3"
	"git"
	"uuid"
	"odbc-mariadb"
	"sudo"
	"subversion"
	"unixodbc"
	"nodejs"
	"npm"
	"ipset"
	"iptables"
	"fail2ban"
	"htop"
	"postfix"
	"tcpdump"
	"sngrep"
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
 	"at"
 	"avahi-daemon"
 	"avahi-utils"
	"libnss-mdns"
	"mailutils"
	# Asterisk package
	"liburiparser1"
	# ffmpeg package
	"libavdevice59"
	# System Admin module
	"python3-mysqldb"
	"python-is-python3"
	# User Control Panel module
	"pkgconf"
	"libicu-dev"
	"libsrtp2-1"
	"libspandsp2"
	"libncurses5"
	"autoconf"
	"libical3"
	"libneon27"
	"libsnmp40"
	"libtonezone"
	"libbluetooth3"
	"libunbound8"
	"libsybdb5"
	"libspeexdsp1"
	"libiksemel3"
	"libresample1"
	"libgmime-3.0-0"
	"libc-client2007e"
	"imagemagick"
)
DEPDEVPKGS=(
	"libsnmp-dev"
	"libtonezone-dev"
	"libpq-dev"
	"liblua5.2-dev"
	"libpri-dev"
	"libbluetooth-dev"
	"libunbound-dev"
	"libspeexdsp-dev"
	"libiksemel-dev"
	"libresample1-dev"
	"libgmime-3.0-dev"
	"libc-client2007e-dev"
	"libncurses-dev"
	"libssl-dev"
	"libxml2-dev"
	"libnewt-dev"
	"libsqlite3-dev"
	"unixodbc-dev"
	"uuid-dev"
	"libasound2-dev"
	"libogg-dev"
	"libvorbis-dev"
	"libcurl4-openssl-dev"
	"libical-dev"
	"libneon27-dev"
	"libsrtp2-dev"
	"libspandsp-dev"
	"libjansson-dev"
	"liburiparser-dev"
	"libavdevice-dev"
	"python-dev-is-python3"
	"default-libmysqlclient-dev"
	"dpkg-dev"
	"build-essential"
	"automake"
	"autoconf"
	"libtool-bin"
	"bison"
	"flex"
)
if [ $dev ]; then
	DEPPKGS=("${DEPPRODPKGS[@]}" "${DEPDEVPKGS[@]}")
else
	DEPPKGS=("${DEPPRODPKGS[@]}")
fi
if [ "$nochrony" != true ]; then
	DEPPKGS+=("chrony")
fi
for i in "${!DEPPKGS[@]}"; do
	pkg_install "${DEPPKGS[$i]}"
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
if [ "$dahdi" ]; then
    message "Installing DAHDI card support..."
    DAHDIPKGS=("asterisk${ASTVERSION}-dahdi"
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
                pkg_install "${DAHDIPKGS[$i]}"
        done
fi

# Install libfdk-aac2
if [ "$noaac" ] ; then
	message "Skipping libfdk-aac2 installation due to noaac option"
else
	pkg_install libfdk-aac2
fi

setCurrentStep "Removing unnecessary packages"
apt-get autoremove -y >> "$log"

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
	if [ "$nochrony" != true ]; then
		sed -i -e "s|^DAEMON_OPTS=\"-F 1\"$|DAEMON_OPTS=\"-F 1 -4\"|" /etc/default/chrony
	fi
fi
# Start the tftp & chrony daemons
systemctl unmask tftpd-hpa.service
systemctl start tftpd-hpa.service
if [ "$nochrony" != true ]; then
	systemctl unmask chrony.service
	systemctl start chrony.service
fi

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
	cat <<EOF >> /etc/vim/vimrc.local
" FreePBX 17 changes - begin
" This file loads the default vim options at the beginning and prevents
" that they are being loaded again later. All other options that will be set,
" are added, or overwrite the default settings. Add as many options as you
" whish at the end of this file.

" Load the defaults
source \$VIMRUNTIME/defaults.vim

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
if [ "$noast" ] ; then
	message "Skipping Asterisk installation due to noasterisk option"
else
	# TODO Need to check if asterisk installed already then remove that and install new ones.
	# Install Asterisk
	setCurrentStep "Installing Asterisk packages."
	install_asterisk $ASTVERSION
fi

# Install PBX dependent packages
setCurrentStep "Installing FreePBX packages"

FPBXPKGS=("sysadmin17"
	   "sangoma-pbx17"
	   "ffmpeg"
   )
for i in "${!FPBXPKGS[@]}"; do
	pkg_install "${FPBXPKGS[$i]}"
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
systemctl restart fail2ban  >> "$log"


if [ "$nofpbx" ] ; then
  message "Skipping FreePBX 17 installation due to nofreepbx option"
else
  setCurrentStep "Installing FreePBX 17"
  pkg_install ioncube-loader-82
  pkg_install freepbx17

  if [ -n "$NPM_MIRROR" ] ; then
    setCurrentStep "Setting environment variable npm_config_registry=$NPM_MIRROR"
    export npm_config_registry="$NPM_MIRROR"
  fi

  # Check if only opensource required then remove the commercial modules
  if [ "$opensourceonly" ]; then
    setCurrentStep "Removing commercial modules"
    fwconsole ma list | awk '/Commercial/ {print $2}' | xargs -I {} fwconsole ma -f remove {} >> "$log"
    # Remove firewall module also because it depends on commercial sysadmin module
    fwconsole ma -f remove firewall >> "$log" || true
  fi

  if [ "$dahdi" ]; then
    fwconsole ma downloadinstall dahdiconfig >> "$log"
    echo 'export PERL5LIB=$PERL5LIB:/etc/wanpipe/wancfg_zaptel' | sudo tee -a /root/.bashrc
  fi

  setCurrentStep "Installing all local modules"
  fwconsole ma installlocal >> "$log"

  setCurrentStep "Upgrading FreePBX 17 modules"
  fwconsole ma upgradeall >> "$log"

  setCurrentStep "Reloading and restarting FreePBX 17"
  fwconsole reload >> "$log"
  fwconsole restart >> "$log"

  if [ "$opensourceonly" ]; then
    # Uninstall the sysadmin helper package for the sysadmin commercial module
    message "Uninstalling sysadmin17"
    apt-get purge -y sysadmin17 >> "$log"
    # Uninstall ionCube loader required for commercial modules and to install the freepbx17 package
    message "Uninstalling ioncube-loader-82"
    apt-get purge -y ioncube-loader-82 >> "$log"
  fi
fi

setCurrentStep "Wrapping up the installation process"
systemctl daemon-reload >> "$log"
if [ ! "$nofpbx" ] ; then
  systemctl enable freepbx >> "$log"
fi

#delete apache2 index.html as we do not need that file
rm -f /var/www/html/index.html

#enable apache mod ssl
a2enmod ssl  >> "$log"

#enable apache mod expires
a2enmod expires  >> "$log"

#enable apache
a2enmod rewrite >> "$log"

#Enabling freepbx apache configuration
if [ ! "$nofpbx" ] ; then 
  a2ensite freepbx.conf >> "$log"
  a2ensite default-ssl >> "$log"
fi

#Setting postfix size to 100MB
postconf -e message_size_limit=102400000

# Disable expose_php for provide less information to attacker
sed -i 's/\(^expose_php = \).*/\1Off/' /etc/php/${PHPVERSION}/apache2/php.ini

# Setting  max_input_vars to 2000
sed -i 's/;max_input_vars = 1000/max_input_vars = 2000/' /etc/php/${PHPVERSION}/apache2/php.ini

# Disable ServerTokens and ServerSignature for provide less information to attacker
sed -i 's/\(^ServerTokens \).*/\1Prod/' /etc/apache2/conf-available/security.conf
sed -i 's/\(^ServerSignature \).*/\1Off/' /etc/apache2/conf-available/security.conf

# Setting pcre.jit to 0
sed -i 's/;pcre.jit=1/pcre.jit=0/' /etc/php/${PHPVERSION}/apache2/php.ini

# Restart apache2
systemctl restart apache2 >> "$log"

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

# Refresh signatures
setCurrentStep "Refreshing modules signatures."
count=1
if [ ! "$nofpbx" ]; then
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


setCurrentStep "FreePBX 17 Installation finished successfully."


############ POST INSTALL VALIDATION ############################################
# Commands for post-installation validation
# Disable automatic script termination upon encountering non-zero exit code to prevent premature termination.
set +e
setCurrentStep "Post-installation validation"

check_services

check_php_version

if [ ! "$nofpbx" ] ; then
 check_freepbx
fi

check_asterisk

execution_time="$(($(date +%s) - start))"
message "Total script Execution Time: $execution_time"
message "Finished FreePBX 17 installation process for $host $kernel"
message "Join us on the FreePBX Community Forum: https://community.freepbx.org/ ";

if [ ! "$nofpbx" ] ; then
  fwconsole motd
fi
