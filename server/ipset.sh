#!/bin/bash

ipset -F gfw
ipset -X gfw
ipset -N gfw iphash
ipset add gfw 8.8.8.8
