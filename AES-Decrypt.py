#!/usr/bin/python

from Crypto.Cipher import AES
import binascii
import base64
import sys

# Known Key (https://github.com/mmozeiko/aes-finder)
KEY = "[KEY]"
print ("Key: "+KEY)

# Known CipherText as argument
ct=sys.argv[1]
ct=base64.b64decode(ct).encode('hex')
print ("CipherText: "+ ct)

# Known IV from Find-IV.py
IV = "[IV]"
IV = binascii.unhexlify(IV)
def encrypt(message, passphrase):
   aes = AES.new(passphrase, AES.MODE_CBC, IV)
   return aes.encrypt(message)

def decrypt(cipher, passphrase):
   aes = AES.new(passphrase, AES.MODE_CBC, IV)
   return aes.decrypt(cipher)

aes = AES.new(KEY, AES.MODE_CBC, IV)
print ("Plain-Text: " + aes.decrypt(binascii.unhexlify(ct)))
