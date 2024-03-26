#!/bin/bash
#
# SPDX-FileCopyrightText: 2024 Penguin PBX Solutions <chris at penguin p b x dot com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Bootstrap of Ansible to install Sangoma FreePBX and Asterisk on Debian 12.
#
# You can run this directly on your TARGET machine.
# It supports the same command line arguments as the main installer.
#

# Exit immediately if a command exits with a non-zero status.
set -e

# Defaults from main installer
SCRIPTVER="1.1-alt"
ASTVERSION=21
AACVERSION="2.0.1-1"
PHPVERSION="8.2"
LOG_FOLDER="/var/log/pbx"
LOG_FILE="${LOG_FOLDER}/freepbx17-install-alt-$(date '+%Y.%m.%d-%H.%M.%S').log"
DISTRIBUTION="$(lsb_release -is)"

# Defaults for ansible
sfpd_install_testing=false
sfpd_install_freepbx=true
sfpd_install_asterisk=true
sfpd_install_ioncube=true

# Check if we are bash shell
if [ "${EUID}" = "" ]; then
  echo "This script must be run in bash"
  exit 1
fi

# Check if we are root privileged
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
fi

# Initialize logging
mkdir -p "${LOG_FOLDER}"
echo "" > $LOG_FILE

# Get parameters
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
	case $1 in
		--testing)
			testrepo=true
			sfpd_install_testing=true # for ansible
			shift # past argument
			;;
		--nofreepbx)
			nofpbx=true
			sfpd_install_freepbx=false # for ansible
			shift # past argument
			;;
		--noasterisk)
			noast=true
			sfpd_install_asterisk=false # for ansible
			shift # past argument
			;;
		--noioncube)
			noioncube=true
			sfpd_install_ioncube=false # for ansible
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

# The rest will tee to the log
{

echo -n "START: " && date

# Include executed commands in the log
set -x

cd /root || exit

# Bootstrap minimal Ansible install, plus git, python3, and lsb-release
apt-get -qq install ansible git python3 lsb-release

# Assume we only downloaded this shell script, so get the repo
git clone https://github.com/chrsmj/sng_freepbx_debian_install.git

# Get to the right branch in the repo
cd sng_freepbx_debian_install/ || exit
git checkout ansible-ize
cd ansible-role/sng_freepbx_debian/ || exit

# Run the Ansible playbook locally (normally over SSH from CONTROL to TARGET)
ansible-playbook \
  --inventory localhost, \
  --become-method=su \
  --connection=local \
  --extra-vars "sfpd_install_asterisk=${sfpd_install_asterisk}" \
  --extra-vars "sfpd_install_freepbx=${sfpd_install_freepbx}" \
  --extra-vars "sfpd_install_ioncube=${sfpd_install_ioncube}" \
  --extra-vars "sfpd_install_testing=${sfpd_install_testing}" \
  --extra-vars "sfpd_asterisk_version=${ASTVERSION}" \
  --extra-vars "sfpd_aac_version=${AACVERSION}" \
  --extra-vars "pngnx_php_version=${PHPVERSION}" \
  playbook.yml

# Clean up the Ansible bits (mostly python libs)
apt-get -qq remove ansible
apt-get -qq autoremove

# Finish the command logging
set +x

echo -n "STOP: " && date

} 2>&1 | tee -a $LOG_FILE
