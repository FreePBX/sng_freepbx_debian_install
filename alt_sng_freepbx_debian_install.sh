#!/bin/bash
#
# SPDX-FileCopyrightText: 2024 Penguin PBX Solutions <chris at penguin p b x dot com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Bootstrap of Ansible to install Sangoma FreePBX and Asterisk on Debian 12.
#
# You can run this directly on your TARGET machine.

# Check if we are bash shell
if [ "x${EUID}" = "x" ]; then
  echo "This script must be run in bash"
  exit 1
fi

# Check if we are root privileged
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root"
  exit 1
fi

# Initialize logging
LOG_FILE='/var/log/pbx/freepbx17-install-alt.log'
mkdir -p '/var/log/pbx/'

# The rest will tee to the log
{

echo -n "START: " && date

# Include executed commands in the log
set -x

cd /root

# Bootstrap minimal Ansible install, plus git, python3, and lsb-release
apt-get -qq install ansible git python3 lsb-release

# Assume we only downloaded this shell script, so get the repo
git clone https://github.com/chrsmj/sng_freepbx_debian_install.git

# Get to the right branch in the repo
cd sng_freepbx_debian_install/
git checkout ansible-ize
cd ansible-role/sng_freepbx_debian/

# Run the Ansible playbook locally (normally over SSH from CONTROL to TARGET)
ansible-playbook -i localhost, --connection=local playbook.yml

# Clean up the Ansible bits (mostly python libs)
apt-get -qq remove ansible
apt-get -qq autoremove

# Finish the command logging
set +x

echo -n "STOP: " && date

} 2>&1 | tee -a $LOG_FILE
