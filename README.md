
```
 ______             _____  ______   __
|  ____|           |  __ \|  _ \ \ / /
| |__ _ __ ___  ___| |__) | |_) \ V /
|  __| '__/ _ \/ _ \  ___/|  _ < > <
| |  | | |  __/  __/ |    | |_) / . \
|_|  |_|  \___|\___|_|    |____/_/ \_\
Your Open Source Asterisk PBX GUI Solution
```

### What?

[FreePBX](http://www.freepbx.org/ "FreePBX Home Page") is an open source GUI (graphical user interface) that controls and manages [Asterisk©](http://www.asterisk.org/ "Asterisk Home Page") (PBX). FreePBX is licensed under GPL.

This is a FreePBX 17 installation script.

This script is to install FreePBX  on the top of vanilla Debian 12.x OS.

[FreePBX](http://www.freepbx.org/ "FreePBX Home Page") is a completely modular GUI for Asterisk written in PHP and Javascript. Meaning you can easily write any module you can think of and distribute it free of cost to your clients so that they can take advantage of beneficial features in [Asterisk](http://www.asterisk.org/ "Asterisk Home Page")

### Setting up a FreePBX system

[See our WIKI](https://sangomakb.atlassian.net/wiki/spaces/FP/pages/9732130/Install+FreePBX)

### License

[This modules code is licensed as GPLv3+](https://www.gnu.org/licenses/gpl-3.0.txt)

### Contributing

To contribute code or modules back into the [FreePBX](http://www.freepbx.org/ "FreePBX Home Page") ecosystem you must fully read our Code License Agreement. We are not able to look at or accept patches or code of any kind until this document is filled out. To view and sign the contributor license agreement you can visit <https://oss-cla.sangoma.com/freepbx/sng_freepbx_debian_install>. Signing this contributor license agreement once allows you to contribute to all open source projects from Sangoma, including FreePBX. Please take a look at [https://sangomakb.atlassian.net/wiki/spaces/FP/pages/10682663/Code+License+Agreement](https://sangomakb.atlassian.net/wiki/spaces/FP/pages/10682663/Code+License+Agreement) for more information

### Issues

Please file bug reports at <https://github.com/FreePBX/issue-tracker/issues>

### How to execute the script

Steps -

1) ssh to the Debian system as 'root'

2) Download the file using `wget`:

```bash
wget https://github.com/FreePBX/sng_freepbx_debian_install/raw/master/sng_freepbx_debian_install.sh -O /tmp/sng_freepbx_debian_install.sh
```

3) Execute the script:

```bash
bash /tmp/sng_freepbx_debian_install.sh
```

The script will install the necessary dependencies for FreePBX, followed by the FreePBX software itself.

The installation duration may vary depending on your internet bandwidth and system capacity.

You can find detailed installation logs at `/var/log/pbx/freepbx17-install.log`.
