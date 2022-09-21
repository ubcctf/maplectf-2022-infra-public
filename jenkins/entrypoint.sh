#!/bin/bash

dockerd-rootless.sh &
sudo sysctl -w kernel.unprivileged_userns_clone=1
/usr/local/bin/jenkins-agent "$@"