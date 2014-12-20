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
        cipher_text = cherryPassword.encrypt(aes_key, original_plaintext)
        decrypted_plaintext = cherryPassword.decrypt(aes_key, cipher_text).decode()
        self.assertEqual(original_plaintext, decrypted_plaintext)

if __name__ == '__main__':
    unittest.main()
