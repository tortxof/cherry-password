#! /usr/bin/env python3

import sqlite3
import bcrypt
import hashlib
from Crypto.Cipher import AES
import codecs
import json
from password import encrypt, decrypt, toHex, fromHex

pwdatabase = 'passwords.db'
jsonfile = open('passwords.json', mode='w')

password = input('Enter password: ')

conn = sqlite3.connect(pwdatabase)
pwHash, salt = conn.execute('select * from master_pass').fetchone()

if bcrypt.checkpw(password, pwHash):
    print('Password is correct.')
    aes_key = bcrypt.kdf(password, salt, 16, 32)
    records = [list(i) for i in conn.execute('select * from passwords')]
    for i in range(len(records)):
        records[i][3] = decrypt(aes_key, records[i][3]).decode()
        records[i][4] = decrypt(aes_key, records[i][4]).decode()
    json.dump(records, jsonfile, indent=2)
else:
    print('Incorrect password.')

jsonfile.close()
conn.close()
