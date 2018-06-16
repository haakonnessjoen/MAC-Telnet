#!/bin/bash

set -e

if [[ $OS_NAME == 'centos' ]]; then

    docker run --privileged -d -ti -e "container=docker"  -v /sys/fs/cgroup:/sys/fs/cgroup -v `pwd`:/MAC-Telnet:rw  centos:centos${OS_VERSION}   /usr/sbin/init
    DOCKER_CONTAINER_ID=$(docker ps | grep centos | awk '{print $1}')
    docker logs $DOCKER_CONTAINER_ID
    docker exec -ti $DOCKER_CONTAINER_ID /bin/bash -c "bash -xe /MAC-Telnet/.docker/centos.sh;
      echo -ne \"------\nEND MAC-Telnet TESTS\n------\nSystemD Units:\n------\n\"; 
      systemctl --no-pager --all --full status;
      echo -ne \"------\nJournalD Logs:\n------\n\";
      journalctl --catalog --all --full --no-pager;"
    docker ps -a
    docker stop $DOCKER_CONTAINER_ID
    docker rm -v $DOCKER_CONTAINER_ID

else

    # OSX, Linux
    ./autogen.sh
    make all

fi


