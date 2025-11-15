'''
The symmetric block cipher NameCipher is given as follows:
The parameters:
Plane space: X = {0…25}
Cipher space: Y = {0…25}
Each block contains m=2 letters.
N = 26
Key space values: The key K is a mXm matrix whose elements are integers in {0, 25}

'''

import math


PAD_CHAR = '$' # Visible padding character used in ciphertext
PAD_NUM = ord('x') - ord('a') # When padding '$' defualts to the same value as if it was 'x'

def is_key_valid(key, N=26):
    """Validate a 2x2 key matrix.

    The function checks:
    - The key is a 2x2 matrix (list of two lists of length two)
    - All entries are integers in [0,25]
    - The determinant modulo N is invertible (gcd(det, N) == 1).

    Args:
        key (list[list[int]]): 2x2 matrix to validate.
        N (int, optional): Modulus. Defaults to 26.

    Returns:
        bool: True when the key is valid, False otherwise.
    """
    try:
        print("\n====================================")
        print("Checking key validity for key:")
        try: # Print the key matrices with justified elements, if fails, print using the built in print for arrays
            print(f"  [{key[0][0]:>3},{key[0][1]:>3}]")
            print(f"  [{key[1][0]:>3},{key[1][1]:>3}]")
        except Exception:
            print(f"  {key}")
        print("------------------------------------")


        # size check
        size_ok = isinstance(key, list) and len(key) == 2 and isinstance(key[0], list) and len(key[0]) == 2 and len(key[1]) == 2
        print(f"{'Matrix size:':30}{'OK' if size_ok else 'NOT VALID'}")
        if not size_ok:
            print("====================================")
            return False

        # element range check
        elements_ok = True
        for row in key:
            for element in row:
                if not isinstance(element, int) or element < 0 or element >= N:
                    elements_ok = False
                    break
            if not elements_ok:
                break
        print(f"{'Elements in range [0,%d]:' % (N-1):30}{'OK' if elements_ok else 'NOT VALID'}")
        if not elements_ok:
            print("====================================")
            return False

        # determinant and gcd
        determinant = (key[0][0] * key[1][1] - key[0][1] * key[1][0]) % N
        print(f"{'Determinant mod N:':30}{determinant}")
        gcd = math.gcd(determinant, N)
        print(f"{'GCD(det, N):':30}{gcd}")
        invertible = gcd == 1
        print(f"{'Key invertible:':30}{'Yes' if invertible else 'No'}")
        print("====================================")
        return invertible
    except Exception as e:
        print("Error while validating key:", e)
        return False


def inverse_2x2_matrix(matrix, N=26):
    """Compute the modular inverse of a 2x2 matrix modulo N.

    Args:
        matrix (list[list[int]]): 2x2 matrix.
        N (int, optional): Modulus. Defaults to 26.

    Returns:
        list[list[int]]: The inverse matrix modulo N.

    Raises:
        ValueError: If the matrix is not invertible modulo N.
    """
    det = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % N
    try:
        det_inv = pow(det, -1, N)
    except ValueError:
        raise ValueError("Matrix determinant has no inverse modulo N")
    inv = [
        [(matrix[1][1] * det_inv) % N, (-matrix[0][1] * det_inv) % N],
        [(-matrix[1][0] * det_inv) % N, (matrix[0][0] * det_inv) % N],
    ]
    return inv


def String_to_int(String, pad_char=PAD_CHAR):
    """Convert a string to a list of integers in the range 0..25.

    Letters are mapped: 'a'->0, 'b'->1, ..., 'z'->25.
    '$' used for padding

    Args:
        String (str): Input text.

    Returns:
        list[int]: Integer representation (letters and '$' as 23).
    """
    result = []
    for ch in String:
        if ch == pad_char:
            result.append(PAD_NUM)
        elif ch.isalpha():
            result.append(ord(ch.lower()) - ord('a'))
        else:
            # skip other characters
            continue
    return result


def int_to_string(integer_array, pad_char=PAD_CHAR, remove_padding=False):
    """Convert a list of integers (0..25) back to a string.

    Args:
        integer_array (list[int]): List of integers to convert.
        pad_char (str, optional): Display character for numeric pad (default '$').
        remove_padding (bool, optional): When True strip trailing pad_char from result.

    Returns:
        str: The converted lowercase string (with pad_char for padding values).
    """
    result = ""
    for integer in integer_array:
        val = int(integer) % 26
        result += chr(val + ord('a'))

    # If remove_padding is True, strip trailing character that corresponds to padding
    if remove_padding and len(result) > 0:
        return result[:-1]
    return result


def matrix_multiply(A, B):
    """
    Multiply matrices A (m x k) and B (k x n) and return m x n result.
    """
    rows_A = len(A)
    cols_A = len(A[0])
    rows_B = len(B)
    cols_B = len(B[0])
    if cols_A != rows_B:
        raise ValueError("Incompatible matrix sizes for multiplication")
    
    # Generate a matrix for result with zeros as the inner elements
    C = [[0 for _ in range(cols_B)] for _ in range(rows_A)]
    
    for i in range(rows_A):
        for j in range(cols_B):
            s = 0
            for k in range(cols_A):
                s += A[i][k] * B[k][j]
            C[i][j] = s
    return C


def NameCipher_encryption(plaintext, encryption_key, second_encryption_key, a, b, N):
    """Encrypt plaintext using the two-stage NameCipher scheme.

    This function performs:
    1. Y = (X * K1 + (a,b)) mod N
    2. Z = (Y * K2 + (a,b)) mod N

    The function pads the input with the padding character '$' when the
    plaintext length is odd. A padding marker is prepended to indicate this.

    Args:
        plaintext (str): Input text to encrypt. Non-letters are ignored.
        encryption_key (list[list[int]]): First 2x2 encryption key K1.
        second_encryption_key (list[list[int]]): Second 2x2 encryption key K2.
        a (int): First affine offset value.
        b (int): Second affine offset value.
        N (int): Modulus.

    Returns:
        str: Ciphertext as a lowercase string (with '$' prefix if padding was used).
    """
    plaintext_integer_array = String_to_int(plaintext)

    # Track if padding is needed
    needs_padding = len(plaintext_integer_array) % 2 != 0

    # pad if odd length
    if needs_padding:
        plaintext_integer_array.append(PAD_NUM)

    # 1st encryption => Y = (X * K1 + (a,b)) mod N
    Y_integer_array = []
    for i in range(0, len(plaintext_integer_array), 2):
        x0 = plaintext_integer_array[i]
        x1 = plaintext_integer_array[i+1]
        block = [x0, x1]
        product = matrix_multiply([block], encryption_key)[0] #! TODO: understand why
        Y_integer_array.extend([(product[0] + a) % N, (product[1] + b) % N])

    # 2nd encryption => Z = (Y * K2 + (a,b)) mod N
    Z_integer_array = []
    for i in range(0, len(Y_integer_array), 2):
        y0 = Y_integer_array[i]
        y1 = Y_integer_array[i+1]
        block = [y0, y1]
        product = matrix_multiply([block], second_encryption_key)[0]
        Z_integer_array.extend([(product[0] + a) % N, (product[1] + b) % N])

    cipher_text = int_to_string(Z_integer_array, pad_char=PAD_CHAR, remove_padding=False)
    
    # If padding was used, prepend PAD_CHAR to mark it
    if needs_padding:
        cipher_text = PAD_CHAR + cipher_text
    
    return cipher_text


def NameCipher_decryption(ciphertext, decryption_key, second_decryption_key, a, b, N):
    """Decrypt ciphertext produced by NameCipher.

    The function reverses the ciphering and returns the
    original plaintext with any padding removed. If the ciphertext 
    starts with PAD_CHAR, it indicates padding was used and is removed.

    Args:
        ciphertext (str): Ciphertext string.
        decryption_key (list[list[int]]): Inverse of K1 modulo N.
        second_decryption_key (list[list[int]]): Inverse of K2 modulo N.
        a (int): Affine offset used in encryption.
        b (int): Affine offset used in encryption.
        N (int): Modulus.

    Returns:
        str: Decrypted plaintext with padding removed.
    """

    # Check if ciphertext starts with PAD_CHAR (indicates padding was used)
    has_padding = len(ciphertext) > 0 and ciphertext[0] == PAD_CHAR
    
    # Remove the padding marker if present
    cipher_no_marker = ciphertext[1:] if has_padding else ciphertext
    
    cipher_integer_array = String_to_int(cipher_no_marker)

    # first reverse EK2 => Y = (Z - (a,b)) * K2_inv
    Y_integer_array = []
    for i in range(0, len(cipher_integer_array), 2):
        z0 = cipher_integer_array[i]
        z1 = cipher_integer_array[i+1] if i+1 < len(cipher_integer_array) else PAD_NUM
        block = [ (z0 - a) % N, (z1 - b) % N ]
        prod = matrix_multiply([block], second_decryption_key)[0]
        Y_integer_array.extend([val % N for val in prod])

    # then reverse EK1 => Plain text = X = (Y - (a,b)) * K1_inv
    X_integer_array = []
    for i in range(0, len(Y_integer_array), 2):
        y0 = (Y_integer_array[i] - a) % N
        y1 = (Y_integer_array[i+1] - b) % N if i+1 < len(Y_integer_array) else PAD_NUM
        block = [y0, y1]
        prod = matrix_multiply([block], decryption_key)[0]
        X_integer_array.extend([val % N for val in prod])

    # Convert integers to string
    decoded = int_to_string(X_integer_array, pad_char=PAD_CHAR, remove_padding=False)

    # If padding was indicated, remove the last character
    if has_padding and len(decoded) > 0:
        decoded = decoded[:-1]

    return decoded


def main():
    """Demonstrate NameCipher encryption and decryption."""
    N = 26
    a = 17
    b = 24

    plaintext_1 = "roni"
    plaintext_2 = "yuval"
    
    # Encryption keys
    encryption_key = [[17, 14], [0, 3]]
    second_encryption_key = [[5, 14], [14, 17]]

    # Validate keys
    if not (is_key_valid(encryption_key, N) and is_key_valid(second_encryption_key, N)):
        print("One or more keys are invalid. Exiting.")
        return 1

    # Compute decryption keys (modular inverses)
    decryption_key = inverse_2x2_matrix(encryption_key, N)
    second_decryption_key = inverse_2x2_matrix(second_encryption_key, N)

    # Encryption
    cipher = NameCipher_encryption(plaintext_1, encryption_key, second_encryption_key, a, b, N)
    cipher_2 = NameCipher_encryption(plaintext_2, encryption_key, second_encryption_key, a, b, N)
    
    print("\n" + "="*50)
    print("ENCRYPTION")
    print("="*50)
    print(f"{'Plaintext 1:':30}{plaintext_1}")
    print(f"{'Ciphertext 1:':30}{cipher}")
    print("-"*50)
    print(f"{'Plaintext 2:':30}{plaintext_2}")
    print(f"{'Ciphertext 2:':30}{cipher_2}")
    print("="*50)

    # Decryption
    decrypted = NameCipher_decryption(cipher, decryption_key, second_decryption_key, a, b, N)
    decrypted_2 = NameCipher_decryption(cipher_2, decryption_key, second_decryption_key, a, b, N)

    print("\n" + "="*50)
    print("DECRYPTION")
    print("="*50)
    print(f"{'Ciphertext 1:':30}{cipher}")
    print(f"{'Decrypted 1:':30}{decrypted}")
    print(f"{'Match:':30}{'✓' if decrypted == plaintext_1 else '✗'}")
    print("-"*50)
    print(f"{'Ciphertext 2:':30}{cipher_2}")
    print(f"{'Decrypted 2:':30}{decrypted_2}")
    print(f"{'Match:':30}{'✓' if decrypted_2 == plaintext_2 else '✗'}")
    print("="*50)

if __name__ == "__main__":
    main()