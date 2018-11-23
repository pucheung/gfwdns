#!/usr/bin/env python3
import re
import os

fadb = open("./adblock.conf")
fgfw = open("./gfw.conf")
fout = open("./tmp.conf","a")
for line in fadb.readlines():
	line=line.strip('\n')
	fout.write('adb/' + line +'\n')

for line in fgfw.readlines():
	line=line.strip('\n')
	m=re.search('([a-zA-Z0-9\-]+)\.(co\.jp|edu|gov|jp|tv|com|net|city|org|info|me|info|be|cc|io|city|us|im|la|ws|biz|de|kr|xyz|in|xxx|es|hk|gl)',line)
	if m:
		fout.write('gfw/' + m.group(0)+ '\n')

fadb.close()
fgfw.close()
fout.close()
os.system("cat tmp.conf |sort | uniq >>update.conf | rm -f tmp.conf")
