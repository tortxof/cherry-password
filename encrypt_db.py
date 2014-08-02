#! /usr/bin/env python3

import sqlite3
import os
import hashlib
import codecs
import bcrypt
from Crypto.Cipher import AES
from password import encrypt, decrypt, toHex, fromHex
import config

pwdatabase = config.dbfile

'''This utility only needs to be run once to convert from an unencrypted database.'''

'''Fill in password here before running'''
password = ''

conn = sqlite3.connect(pwdatabase)
salt = [i for i in conn.execute('select salt from master_pass')][0][0]
print(salt)
aes_key = bcrypt.kdf(password, salt, 16, 32)
print(toHex(aes_key))
rowids = [i[0] for i in conn.execute('select rowid from passwords')]
print(rowids)
for rowid in rowids:
    password = [i for i in conn.execute('select password from passwords where rowid=?', (rowid,))][0][0]
    other = [i for i in conn.execute('select other from passwords where rowid=?', (rowid,))][0][0]
    print(rowid, password, other)
    enc_password = encrypt(aes_key, password)
    enc_other = encrypt(aes_key, other)
    print(rowid, enc_password, enc_other)
    conn.execute('update passwords set password=?, other=? where rowid=?', (enc_password, enc_other, rowid))

conn.commit()
conn.close()
