#! /usr/bin/env python3

import password as cherryPassword
import unittest
import os
import bcrypt

class PasswordEncryption(unittest.TestCase):
    def test_round_trip_encryption(self):
        '''Encryption followed by decryption should return back our original input.'''
        original_plaintext = 'This is our test input.'
        password = 'testpassword'
        salt = os.urandom(16)
        aes_key = bcrypt.kdf(password, salt, 16, 32)
        ciphertext = cherryPassword.encrypt(aes_key, original_plaintext)
        decrypted_plaintext = cherryPassword.decrypt(aes_key, ciphertext).decode()
        self.assertEqual(original_plaintext, decrypted_plaintext)

    def test_known_ciphertext(self):
        '''Test decryption of known ciphertext.'''
        cipher_text = b'\xef\xca}\xac\xee\xd1\xd9|\xc4\x95\xee\x86\xa0\x8b\x0b\x1c^P\xf9p\x1b\xc1\x0e\xfb\xfe\x17\xd5\xc7\x8b\xfe\x99\xd9\xbeF\xf3z\x1b\xdco'
        plaintext = 'This is our test input.'
        password = 'testpassword'
        salt = b'\x01\xdc\xc4\xd9&\xceJ\xcb\xca\x1f\x05u\xb5r\x92H'
        aes_key = bcrypt.kdf(password, salt, 16, 32)
        decrypted_plaintext = cherryPassword.decrypt(aes_key, cipher_text).decode()
        self.assertEqual(plaintext, decrypted_plaintext)

if __name__ == '__main__':
    unittest.main()
