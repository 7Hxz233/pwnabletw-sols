FROM ubuntu:16.04
MAINTAINER ddaa
RUN apt-get update
RUN apt-get install xinetd -y
RUN useradd -m bash
RUN chmod 774 /tmp
RUN chmod -R 774 /var/tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run
RUN chmod 1733 /tmp /var/tmp /dev/shm
RUN chown -R root:root /home/bash
RUN setcap cap_sys_chroot+ep /usr/sbin/chroot 
CMD ["/run.sh"]
