#! /usr/bin/env python3

import sqlite3
import os
import hashlib
import codecs
import bcrypt
from Crypto.Cipher import AES
import config

pwdatabase = config.dbfile

def encrypt(key, data):
    '''Encrypts data with AES cipher using key and random iv.'''
    key = hashlib.sha256(key.encode()).digest()[:AES.block_size]
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return iv + cipher.encrypt(data)

def decrypt(key, data):
    '''Decrypt ciphertext using key'''
    key = hashlib.sha256(key.encode()).digest()[:AES.block_size]
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(data)[AES.block_size:]

