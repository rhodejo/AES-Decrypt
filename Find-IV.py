#!/usr/bin/python
from Crypto.Cipher import AES
import binascii

# Known KEY (https://github.com/mmozeiko/aes-finder)
KEY = "[KEY]"
print ("Key: "+KEY)

# Known Plaintext
pt="[PlainText]"
print ("Plain-Text: "+ pt)

# Known CipherText
ct="[CipherText]"
print ("CipherText: "+ ct)

# use null bytes to minimize effect on output
IV = "\x00"*16
def encrypt(message, passphrase):
   aes = AES.new(passphrase, AES.MODE_CBC, IV)
   return aes.encrypt(message)

def decrypt(cipher, passphrase):
   aes = AES.new(passphrase, AES.MODE_CBC, IV)
   return aes.decrypt(cipher)

# now we can decrypt ct and xor against the pt to recover the IV
wpt = decrypt(binascii.unhexlify(ct), KEY)
IV = ""
for i in range(16):
   p = ord(pt[i]) ^ ord(wpt[i])
   IV += "%02X" % p
print ("IV HEX: " + IV)
IV = binascii.unhexlify(IV)

# sanity check:
aes = AES.new(KEY, AES.MODE_CBC, IV)
print ("Sanity check: " + aes.decrypt(binascii.unhexlify(ct)))
