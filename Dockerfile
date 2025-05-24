FROM geerlingguy/docker-debian12-ansible:latest
RUN apt-get -qq update && apt-get -qq install git lsb-release
COPY alt_sng_freepbx_debian_install.sh /alt_sng_freepbx_debian_install.sh
ENTRYPOINT ["/alt_sng_freepbx_debian_install.sh"]
