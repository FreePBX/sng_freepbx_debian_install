# sng_freepbx_debian

An Ansible Role for Installing FreePBX 17 on Debian 12.

Copyright 2024 Penguin PBX Solutions <chris at penguin p b x dot com>

Licensed under the GPLv3+

## BETA SOFTWARE NOT FOR USE IN PRODUCTION

**Follows the sng_freepbx_debian_install.sh bash script fairly closely.**

*Based on lots of previous work in the [pngnx23299](https://github.com/chrsmj/pngnx23299)
Ansible Role from [Penguin PBX Solutions](https://PenguinPBX.com).*

---

## Instructions

0. First, install Debian 12 on your TARGET machine (outside the scope of this document.)
   *The rest of these instructions you will run on your CONTROL machine.*

1. Confirm you can SSH (as a regular user, not root) to the Debian 12 TARGET machine:

        ssh TARGET

   Got shell? Good! Stay connected. su to root on TARGET and install python3 and lsb-release:

        su -
        apt-get -y install python3 lsb-release

   Keep this terminal open. Continue with step 2 in *another* terminal on CONTROL.

2. Install ansible, sshpass, and git (assuming your CONTROL is Debian):

        sudo apt-get install ansible sshpass git

3. Clone the freepbx/sng_freepbx_debian_install repository:

        git clone https://github.com/FreePBX/sng_freepbx_debian_install.git

4. Change into the ansible-role directory:

        cd sng_freepbx_debian_install/ansible-role/sng_freepbx_debian

5. Run Ansible. The system will prompt for your SSH password and then ROOT password:

        ansible-playbook -k -K --become-method=su -i TARGET, playbook.yml

   (The comma after the TARGET name is very important.)

Your install should complete in about 10-15 minutes.

---

## Notes

This role attempts to be as idempotent as possible,
meaning you can run it multiple times against the same TARGET,
without completely clobbering your existing setup,
and get yourself back to a reasonable state.

For example, instead of concatenating configuration files,
such as the bash installer script does, this ansible role will
instead copy files and templates in to place. The role will also
check if the desired file state exists before making changes.
