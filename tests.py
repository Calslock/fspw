from wallet import hash_and_encrypt, hash_hmac, encrypt, decrypt, createsalt
from parameterized import parameterized
import unittest
from unittest_dataprovider import data_provider

password = "password"
masterkey = "masterkey"
encodedpass = b'nk\x13\xc2\x0f\xa2/\x9f'


class TestEncryptionMethods(unittest.TestCase):
    # SHA-256
    def test_hash_and_encrypt(self):
        actual = hash_and_encrypt(password)
        expected = '07b4c9aebf80f9b270f494354aa2f25a0f89d1732c9fe9d8e8bd34bc281425ab40837210a2921018b9028eab0d' \
                   'fe05c04a4bcd26fdec7d3488685785504e1789626bfb2aac0230427c969d0552e25642169099bc05f837e0c0dc' \
                   '510fdb4dd57211d82fa9563290a5d1ac26242b0257b39a61b476279aa0662047a08a01a1515b'
        self.assertEqual(actual, expected)

    # HMAC
    def test_hash_hmac(self):
        actual = hash_hmac(password)
        expected = "0ce48ed10fba3657fadd4193aaac86b8bfe94aa50982fef0e1e2d8162fb90a805a38304e3b792bd6486c0110b5" \
                   "3aef34b57d4e0d3b28adbe320cab725d5dd29c"
        self.assertEqual(actual, expected)

    # encrypting with AES
    def test_encrypt(self):
        actual = encrypt(password, masterkey)
        expected = encodedpass
        self.assertEqual(actual, expected)

    # decrypting with AES
    def test_decrypt(self):
        actual = decrypt(encodedpass, masterkey)
        expected = password
        self.assertEqual(actual, expected)


class TestCreateSalt(unittest.TestCase):
    # creating salt
    @parameterized.expand([
        ["empty", 0, len(createsalt(0)), type(createsalt(0)) is str],
        ["positive_small", 16, len(createsalt(16)), type(createsalt(16)) is str],
        ["positive_big", 65536, len(createsalt(65536)), type(createsalt(65536)) is str],
        ["negative", 0, len(createsalt(-1)), type(createsalt(-1)) is str]
    ])
    def test_create_salt(self, name, length, actual_length, var_type):
        self.assertEqual(length, actual_length)
        self.assertTrue(var_type)


class TestEncryptionMethodsDataProvider(unittest.TestCase):
    @staticmethod
    def data():
        return (
            ("password",
             "masterkey",
             b'nk\x13\xc2\x0f\xa2/\x9f',
             '07b4c9aebf80f9b270f494354aa2f25a0f89d1732c9fe9d8e8bd34bc281425ab40837210a2921018b9028eab0d' \
             'fe05c04a4bcd26fdec7d3488685785504e1789626bfb2aac0230427c969d0552e25642169099bc05f837e0c0dc' \
             '510fdb4dd57211d82fa9563290a5d1ac26242b0257b39a61b476279aa0662047a08a01a1515b',
             "0ce48ed10fba3657fadd4193aaac86b8bfe94aa50982fef0e1e2d8162fb90a805a38304e3b792bd6486c0110b5" \
             "3aef34b57d4e0d3b28adbe320cab725d5dd29c",
             ),
        )

    @data_provider(data)
    def testdp_hash_and_encrypt(self, dppassword, dpmasterkey, dpencodedpass, dpsha256, dphmac):
        result = hash_and_encrypt(dppassword)
        self.assertEqual(result, dpsha256)

    @data_provider(data)
    def testdp_hash_hmac(self, dppassword, dpmasterkey, dpencodedpass, dpsha256, dphmac):
        result = hash_hmac(dppassword)
        self.assertEqual(result, dphmac)

    @data_provider(data)
    def testdp_encrypt(self, dppassword, dpmasterkey, dpencodedpass, dpsha256, dphmac):
        result = encrypt(dppassword, dpmasterkey)
        self.assertEqual(result, dpencodedpass)

    @data_provider(data)
    def testdp_decrypt(self, dppassword, dpmasterkey, dpencodedpass, dpsha256, dphmac):
        result = decrypt(dpencodedpass, dpmasterkey)
        self.assertEqual(result, dppassword)


class TestCreateSaltDataProvider(unittest.TestCase):
    @staticmethod
    def data():
        return (
            (0, len(createsalt(0)), type(createsalt(0)) is str),
            (16, len(createsalt(16)), type(createsalt(16)) is str),
            (65536, len(createsalt(65536)), type(createsalt(65536)) is str),
            (0, len(createsalt(-1)), type(createsalt(-1)) is str),
        )

    @data_provider(data)
    def testdp_create_salt(self, length, actual_length, var_type):
        self.assertEqual(length, actual_length)
        self.assertTrue(var_type)