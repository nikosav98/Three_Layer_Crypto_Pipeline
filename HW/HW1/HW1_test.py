import os
import sys
import unittest

# Ensure the HW1 module (HW1.py) in the same folder is importable
TEST_DIR = os.path.dirname(__file__)
if TEST_DIR not in sys.path:
	sys.path.insert(0, TEST_DIR)

import HW1 as hw


class TestHW1(unittest.TestCase):
	def setUp(self):
		# reuse parameters from the example `main()` in HW1.py
		self.N = 26
		self.a = 17
		self.b = 24
		self.encryption_key = [[17, 14], [0, 3]]
		self.second_encryption_key = [[5, 14], [14, 17]]

	def test_padding_char_constant(self):
		# ensure padding character was changed to '$'
		self.assertEqual(hw.PAD_CHAR, '$', 'PAD_CHAR should be set to $')

	def test_is_key_valid_accepts_valid_key(self):
		self.assertTrue(hw.is_key_valid(self.encryption_key, self.N),
				"Valid key was rejected — expected True from is_key_valid")

	def test_is_key_valid_rejects_wrong_size(self):
		bad = [1, 2, 3]
		self.assertFalse(hw.is_key_valid(bad, self.N),
				 "Key with wrong shape should be invalid")

	def test_is_key_valid_rejects_out_of_range_elements(self):
		bad = [[27, 0], [0, 1]]
		self.assertFalse(hw.is_key_valid(bad, self.N),
				 "Key with element out of range should be invalid")

	def test_is_key_valid_rejects_noninvertible_key(self):
		# determinant is 4 -> gcd(4,26) == 2 -> not invertible
		noninv = [[2, 0], [0, 2]]
		self.assertFalse(hw.is_key_valid(noninv, self.N),
				 "Non-invertible key must be rejected (gcd(det,N)!=1)")

	def test_inverse_2x2_matrix_raises_on_noninvertible(self):
		noninv = [[2, 0], [0, 2]]
		with self.assertRaises(ValueError, msg="inverse_2x2_matrix should raise on non-invertible determinant"):
			hw.inverse_2x2_matrix(noninv, self.N)

	def test_matrix_multiply_raises_on_incompatible_sizes(self):
		A = [[1, 2, 3]]  # 1x3
		B = [[1, 2], [3, 4]]  # 2x2 -> incompatible (3 != 2)
		with self.assertRaises(ValueError, msg="matrix_multiply should raise on incompatible dimensions"):
			hw.matrix_multiply(A, B)

	def test_string_to_int_and_back_roundtrip(self):
		s = f"Ab{hw.PAD_CHAR}c!"
		ints = hw.String_to_int(s, pad_char=hw.PAD_CHAR)
		# String_to_int maps PAD_CHAR to PAD_NUM (23, same as 'x')
		expected_ints = [0, 1, 23, 2]
		self.assertEqual(ints, expected_ints, "String_to_int should map PAD_CHAR to PAD_NUM")

		s_back = hw.int_to_string(ints, pad_char=hw.PAD_CHAR, remove_padding=False)
		# int_to_string maps numbers 0-25 to letters (23 -> 'x')
		self.assertEqual(s_back, 'abxc', "int_to_string should map 23 to 'x'")

	def test_int_to_string_remove_padding(self):
		ints = [0, 1, 0, 0]
		shown = hw.int_to_string(ints, pad_char=hw.PAD_CHAR, remove_padding=False)
		self.assertEqual(shown, 'abaa', "int_to_string should map numbers to letters")
		# simulate visible pad replacement and removal
		shown_with_pad = shown[:-2] + hw.PAD_CHAR + hw.PAD_CHAR
		stripped = shown_with_pad.rstrip(hw.PAD_CHAR)
		self.assertEqual(stripped, 'ab', "Simulated pad removal should strip trailing pad chars")

	def test_encryption_and_decryption_roundtrip(self):
		plaintext = 'yuvalroni'
		# verify keys valid first (sanity)
		self.assertTrue(hw.is_key_valid(self.encryption_key, self.N))
		self.assertTrue(hw.is_key_valid(self.second_encryption_key, self.N))

		dec_key = hw.inverse_2x2_matrix(self.encryption_key, self.N)
		dec_key2 = hw.inverse_2x2_matrix(self.second_encryption_key, self.N)

		cipher = hw.NameCipher_encryption(plaintext, self.encryption_key, self.second_encryption_key, self.a, self.b, self.N)
		self.assertIsInstance(cipher, str, "Encryption should return a string")

		decrypted = hw.NameCipher_decryption(cipher, dec_key, dec_key2, self.a, self.b, self.N)
		self.assertEqual(decrypted, plaintext, "Decryption should recover exact plaintext")

	def test_empty_string_roundtrip(self):
		plaintext = ''
		dec_key = hw.inverse_2x2_matrix(self.encryption_key, self.N)
		dec_key2 = hw.inverse_2x2_matrix(self.second_encryption_key, self.N)
		cipher = hw.NameCipher_encryption(plaintext, self.encryption_key, self.second_encryption_key, self.a, self.b, self.N)
		self.assertEqual(cipher, '', 'Encrypting empty string should return empty ciphertext')
		decrypted = hw.NameCipher_decryption(cipher, dec_key, dec_key2, self.a, self.b, self.N)
		self.assertEqual(decrypted, '', 'Decrypting empty ciphertext should return empty plaintext')

	def test_single_letter_padding_marker(self):
		plaintext = 'a'
		dec_key = hw.inverse_2x2_matrix(self.encryption_key, self.N)
		dec_key2 = hw.inverse_2x2_matrix(self.second_encryption_key, self.N)
		cipher = hw.NameCipher_encryption(plaintext, self.encryption_key, self.second_encryption_key, self.a, self.b, self.N)
		# encryption of odd-length plaintext should start with PAD_CHAR marker
		self.assertTrue(cipher.startswith(hw.PAD_CHAR), 'Ciphertext should start with PAD_CHAR for odd-length input')
		decrypted = hw.NameCipher_decryption(cipher, dec_key, dec_key2, self.a, self.b, self.N)
		self.assertEqual(decrypted, plaintext, 'Decryption should recover original plaintext exactly')

	def test_x_character_roundtrip(self):
		# ensure real 'x' characters survive round-trip and are not confused with padding
		plaintext = 'x'
		dec_key = hw.inverse_2x2_matrix(self.encryption_key, self.N)
		dec_key2 = hw.inverse_2x2_matrix(self.second_encryption_key, self.N)
		cipher = hw.NameCipher_encryption(plaintext, self.encryption_key, self.second_encryption_key, self.a, self.b, self.N)
		# Ciphertext should start with PAD_CHAR since plaintext length is odd
		self.assertTrue(cipher.startswith(hw.PAD_CHAR), "Ciphertext should start with PAD_CHAR for odd-length plaintext")
		decrypted = hw.NameCipher_decryption(cipher, dec_key, dec_key2, self.a, self.b, self.N)
		self.assertEqual(decrypted, plaintext, "Decryption should recover 'x' exactly")

	def test_multiple_x_roundtrip(self):
		plaintext = 'xxx'
		dec_key = hw.inverse_2x2_matrix(self.encryption_key, self.N)
		dec_key2 = hw.inverse_2x2_matrix(self.second_encryption_key, self.N)
		cipher = hw.NameCipher_encryption(plaintext, self.encryption_key, self.second_encryption_key, self.a, self.b, self.N)
		# Odd-length plaintext should result in ciphertext starting with PAD_CHAR
		self.assertTrue(cipher.startswith(hw.PAD_CHAR), "Ciphertext should start with PAD_CHAR for odd-length plaintext")
		decrypted = hw.NameCipher_decryption(cipher, dec_key, dec_key2, self.a, self.b, self.N)
		self.assertEqual(decrypted, plaintext, "Decryption should recover exact plaintext")

	def test_NameCipher_decryption_raises_on_bad_decryption_key_shape(self):
		# Create a valid ciphertext then pass an invalid-shaped decryption key to provoke a clear error
		plaintext = 'test'
		cipher = hw.NameCipher_encryption(plaintext, self.encryption_key, self.second_encryption_key, self.a, self.b, self.N)
		# decryption_key must be 2x2; give a key with 1 row to provoke matrix_multiply size check
		bad_dec_key = [[1, 2, 3]]
		dec_key2 = hw.inverse_2x2_matrix(self.second_encryption_key, self.N)
		with self.assertRaises(ValueError, msg="NameCipher_decryption should raise when decryption_key has incompatible dimensions"):
			hw.NameCipher_decryption(cipher, bad_dec_key, dec_key2, self.a, self.b, self.N)


if __name__ == '__main__':
	unittest.main()

