# -*- coding: utf-8 -*-

import argparse
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

f = open("autosar_publickey.pem",'r')
key = RSA.import_key(f.read())

print()
print('The decimal equivalent of the public modulas is')
print()
print()

for i in range(383,-1,-1):
    print((key.n>>(8*i))&(0xff),end=' ')

print()
print()
print('The public exponent is')
print()

print((key.e>>(16))&(0xff),end=' ')
print((key.e>>(8))&(0xff),end=' ')
print((key.e)&(0xff),end=' ')
print()
print()