#!/bin/sh

make && insmod ./xensa108.ko && (strings /proc/xensa108 ; rmmod xensa108)
