"""Utility helpers for cryptography exercises.

This module provides small, dependency-free helpers useful when
implementing or testing symmetric-key, public-key and digital signature
algorithms. It intentionally does NOT implement full cryptographic
algorithms — only reusable low-level utilities.
"""

from __future__ import annotations

import binascii
import secrets
import math
from typing import Iterable, List, Tuple, Optional


# Alphabet padding defaults used by exercises
PAD_CHAR = '$'
PAD_NUM = ord('x') - ord('a')


def _print_separator(char: str = '=') -> None:
	"""Print a separator line for console output."""
	print(char * 50)


def _print_label_value(label: str, value) -> None:
	"""Print a label and a value in aligned columns."""
	print(f"{label:35}{value}")


def chunk_list(seq: Iterable, size: int) -> Iterable[List]:
	"""Yield successive chunks of ``size`` from ``seq``.

	Example: list(chunk_list([1,2,3,4], 2)) -> [[1,2],[3,4]]
	"""
	s = list(seq)
	for i in range(0, len(s), size):
		yield s[i:i + size]


def pad_text_to_block(text: str, block_size: int = 2, pad_char: str = PAD_CHAR) -> Tuple[str, bool]:
	"""Pad ``text`` to a multiple of ``block_size`` using ``pad_char``.

	Returns a tuple (padded_text, padded_flag).
	"""
	if block_size <= 0:
		raise ValueError("block_size must be > 0")
	arr = list(text)
	padded = False
	while len(arr) % block_size != 0:
		arr.append(pad_char)
		padded = True
	return ("".join(arr), padded)


def String_to_int(s: str, pad_char: str = PAD_CHAR) -> List[int]:
	"""Convert a string to a list of integers 0..25 using a->0 mapping.

	Non-letter characters are ignored except for ``pad_char`` (mapped to PAD_NUM).
	"""
	result: List[int] = []
	for ch in s:
		if ch == pad_char:
			result.append(PAD_NUM)
		elif ch.isalpha():
			result.append(ord(ch.lower()) - ord('a'))
		else:
			continue
	return result


def int_to_string(integer_array: Iterable[int], pad_char: str = PAD_CHAR, remove_padding: bool = False) -> str:
	"""Convert integers (0..25) back to a lowercase string.

	If ``remove_padding`` is True the final character is stripped.
	"""
	result = ""
	for integer in integer_array:
		val = int(integer) % 26
		result += chr(val + ord('a'))
	if remove_padding and len(result) > 0:
		return result[:-1]
	return result


def matrix_multiply(A: List[List[int]], B: List[List[int]]) -> List[List[int]]:
	"""Multiply matrices A (m x k) and B (k x n) -> m x n.

	Raises ValueError for incompatible shapes.
	"""
	if not A or not B:
		raise ValueError("Empty matrix")
	rows_A, cols_A = len(A), len(A[0])
	rows_B, cols_B = len(B), len(B[0])
	if cols_A != rows_B:
		raise ValueError("Incompatible matrix sizes for multiplication")
	result = [[0 for _ in range(cols_B)] for _ in range(rows_A)]
	for i in range(rows_A):
		for j in range(cols_B):
			s = 0
			for k in range(cols_A):
				s += A[i][k] * B[k][j]
			result[i][j] = s
	return result


def print_2x2_matrix(matrix: List[List[int]]) -> None:
	"""Print a 2x2 matrix in formatted style with validation."""
	if not isinstance(matrix, list) or len(matrix) != 2:
		raise ValueError("Matrix must be a 2×2 list of lists.")
	for row in matrix:
		if not isinstance(row, list) or len(row) != 2:
			raise ValueError("Matrix must be 2×2.")
	for row in matrix:
		for element in row:
			if not isinstance(element, (int, float)):
				raise ValueError("Matrix elements must be numeric.")
	print(f"  [{matrix[0][0]:>3},{matrix[0][1]:>3}]")
	print(f"  [{matrix[1][0]:>3},{matrix[1][1]:>3}]")


def egcd(a: int, b: int) -> Tuple[int, int, int]:
	"""Extended GCD: return (g, x, y) with a*x + b*y = g = gcd(a, b)."""
	if b == 0:
		return (a, 1, 0)
	else:
		g, x1, y1 = egcd(b, a % b)
		return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
	"""Modular inverse of a modulo m. Raises ValueError if inverse doesn't exist."""
	a = a % m
	try:
		return pow(a, -1, m)
	except TypeError:
		g, x, _ = egcd(a, m)
		if g != 1:
			raise ValueError("No modular inverse")
		return x % m
	except ValueError:
		g, x, _ = egcd(a, m)
		if g != 1:
			raise ValueError("No modular inverse")
		return x % m


def inverse_2x2_matrix(matrix: List[List[int]], N: int = 26) -> List[List[int]]:
	"""Compute modular inverse of a 2x2 matrix modulo N. Raises ValueError if not invertible."""
	det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % N
	det_inv = modinv(det, N)
	inv = [
		[(matrix[1][1] * det_inv) % N, (-matrix[0][1] * det_inv) % N],
		[(-matrix[1][0] * det_inv) % N, (matrix[0][0] * det_inv) % N],
	]
	return inv


def is_prime(n: int, k: int = 5) -> bool:
	"""Probabilistic Miller-Rabin primality test.

	k is the number of rounds; small n are handled deterministically.
	"""
	if n <= 1:
		return False
	small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
	for p in small_primes:
		if n % p == 0:
			return n == p
	d = n - 1
	r = 0
	while d % 2 == 0:
		d //= 2
		r += 1
	for _ in range(k):
		a = secrets.randbelow(n - 3) + 2
		x = pow(a, d, n)
		if x == 1 or x == n - 1:
			continue
		composite = True
		for _ in range(r - 1):
			x = pow(x, 2, n)
			if x == n - 1:
				composite = False
				break
		if composite:
			return False
	return True


def int_to_bytes(n: int, length: Optional[int] = None) -> bytes:
	"""Convert non-negative integer to big-endian bytes; minimal length if None."""
	if n < 0:
		raise ValueError("n must be non-negative")
	if length is None:
		length = (n.bit_length() + 7) // 8 or 1
	return n.to_bytes(length, byteorder='big')


def bytes_to_int(b: bytes) -> int:
	"""Convert big-endian bytes to integer."""
	return int.from_bytes(b, byteorder='big')


def to_hex(b: bytes) -> str:
	"""Return lowercase hex string for bytes (no prefix)."""
	return binascii.hexlify(b).decode('ascii')


def from_hex(h: str) -> bytes:
	"""Convert hex string (with optional 0x prefix) to bytes."""
	if h.startswith('0x'):
		h = h[2:]
	return binascii.unhexlify(h)


def safe_random_bits(bits: int) -> int:
	"""Return a cryptographically secure random integer of ``bits`` bits."""
	if bits <= 0:
		raise ValueError("bits must be > 0")
	return secrets.randbits(bits)


__all__ = [
	'_print_separator', '_print_label_value', 'chunk_list', 'pad_text_to_block',
	'String_to_int', 'int_to_string', 'matrix_multiply', 'print_2x2_matrix',
	'egcd', 'modinv', 'inverse_2x2_matrix', 'is_prime', 'int_to_bytes',
	'bytes_to_int', 'to_hex', 'from_hex', 'safe_random_bits', 'PAD_CHAR', 'PAD_NUM'
]

