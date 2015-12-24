#!/bin/sh
set -x
make clean
make
rmmod sys_submitjob
insmod sys_submitjob.ko
