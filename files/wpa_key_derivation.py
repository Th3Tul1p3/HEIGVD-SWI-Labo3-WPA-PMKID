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

def findBeacon(capture):
    """
    Cette fonction détecte et retourne le premier Beacon de la capture
    """
    for frame in capture:
        # si la trame est de type et sous-type Beacon, on la retourne 
        if frame.type == 0 and frame.subtype == 8:
            return frame

def findAuthentication(APmac, capture):
    """
    Cette fonction détecte et retourne le mac du client en sa basant sur les messages d'authentification
    """
    for frame in capture:
        # Si la trame est de type et de sous-type authentification avec l'adresse MAC de l'AP
        if frame.type == 0 and frame.subtype == 11 and a2b_hex(frame.addr2.replace(':', '')) == APmac :
            return a2b_hex(frame.addr1.replace(':', ''))

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

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase = "actuelle"
A = "Pairwise key expansion"  # this string is used in the pseudo-random function

# recherche du premier beacon dans la capture
Beacon = findBeacon(wpa)
# Récupération du SSID
ssid = Beacon.info.decode("utf-8")
# Récupération de l'adresse MAC de l'AP
APmac = a2b_hex(Beacon.addr2.replace(':', ''))          # "cebcc8fdcab7"
# Récupération de l'adresse MAC du client
Clientmac = findAuthentication(APmac, wpa)              # "0013efd015bd"

# detection du handshake et renvoi des 4 trames
handshake = find4wayHandShake(wpa)
# Récupération du PMKID
PMKID = raw(handshake[0])[193:-4]

print("\n\nValues used to derivate keys")
print("============================")
print("Passphrase: ", passPhrase, "\n")
print("SSID: ", ssid, "\n")
print("AP Mac: ", b2a_hex(APmac), "\n")
print("CLient Mac: ", b2a_hex(Clientmac), "\n")
print("PMKID : ", bytes_hex(PMKID))

