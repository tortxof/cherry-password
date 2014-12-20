#! /usr/bin/env python3

import password as cherryPassword
import unittest
import os
import bcrypt

class PasswordEncryption(unittest.TestCase):
    def setUp(self):
        self.plaintext = 'This is our test input.'
        self.ciphertext = b'\xef\xca}\xac\xee\xd1\xd9|\xc4\x95\xee\x86\xa0\x8b\x0b\x1c^P\xf9p\x1b\xc1\x0e\xfb\xfe\x17\xd5\xc7\x8b\xfe\x99\xd9\xbeF\xf3z\x1b\xdco'
        self.password = 'testpassword'
        self.salt = b'\x01\xdc\xc4\xd9&\xceJ\xcb\xca\x1f\x05u\xb5r\x92H'
        self.aes_key = b'\xa9+BYT\x045\xe1\xf8\x90\xf6\xfe\xa1\xf5\x05\xd1'

    def test_round_trip_encryption(self):
        '''Encryption followed by decryption should return back our original input.'''
        ciphertext = cherryPassword.encrypt(self.aes_key, self.plaintext)
        decrypted_plaintext = cherryPassword.decrypt(self.aes_key, ciphertext).decode()
        self.assertEqual(self.plaintext, decrypted_plaintext)

    def test_known_ciphertext(self):
        '''Test decryption of known ciphertext.'''
        decrypted_plaintext = cherryPassword.decrypt(self.aes_key, self.ciphertext).decode()
        self.assertEqual(self.plaintext, decrypted_plaintext)

    def test_bad_plaintext_input(self):
        '''Exception should be thrown when trying to encrypt anything other than str or bytes.'''
        password = 'testpassword'
        salt = b'\x01\xdc\xc4\xd9&\xceJ\xcb\xca\x1f\x05u\xb5r\x92H'
        aes_key = bcrypt.kdf(password, salt, 16, 32)
        for i in (1, 0.1):
            self.assertRaises(TypeError, cherryPassword.encrypt, aes_key, i)

if __name__ == '__main__':
    unittest.main()
