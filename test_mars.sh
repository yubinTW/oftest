#! /bin/bash

HOST=210.63.204.29
INTERFACE=enp0s3
DEBUG=info

echo "Start testing `date +%Y/%m/%d-%H:%M:%S`"

sudo ./oft --host=${HOST} -i 1@${INTERFACE} --of-version=1.3 --mars=MARS --test-dir=mars --disable-ipv6 --debug=${DEBUG} account_test

echo "End testing `date +%Y/%m/%d-%H:%M:%S`"