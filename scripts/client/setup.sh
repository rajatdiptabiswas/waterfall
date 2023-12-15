#!/usr/bin/bash

cd /home/rajat/github/waterfall/client
./client-setup.sh

export SSLKEYLOGFILE=/home/rajat/github/waterfall/client/sslkeylogfile.txt

source py27/bin/activate

ping google.com -c1

