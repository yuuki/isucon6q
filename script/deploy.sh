#!/bin/bash

set -ex

IPADDR=$1
if [ -z "$IPADDR" ]; then
    exit 1
fi

GOOS=linux GOARCH=amd64 make
ssh isucon@"$IPADDR" "sudo service isuda.go stop && sudo service isutar.go stop"
scp isuda isutar isucon@"$IPADDR":/home/isucon/webapp/go/
ssh isucon@"$IPADDR" "sudo service isuda.go start && sudo service isutar.go start"
