#!/usr/bin/env bash

mkdir -P /usr/local/etc/godns
mv godns /usr/local/bin/godns
mv config.json /usr/local/etc/godns/
mv ipset.sh /usr/local/etc/godns/
mv -R www /usr/local/etc/godns/
echo "nohup /usr/local/bin/godns >>/var/log/godns.log &" >> /etc/rc.d/rc.local

