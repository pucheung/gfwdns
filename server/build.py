#!/usr/bin/env python

import os


os.chdir("../")
status = os.system("go build godns.go config.go handle.go httpmanage.go")
if status != 0:
	print("Go Build Error")
	print(status)

os.system("mv godns server/")
os.system("tar cvf server.tar.xz server/")
os.system("mv server.tar.xz server/")
