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

EXIT_COMMANDS = ("exit", "quit")
PAD_CHAR = '$' # Visible padding character used in ciphertext
PAD_NUM = ord('x') - ord('a') # When padding '$' defualts to the same value as if it was 'x'

# Global width used for separators and centered titles
SEPARATOR_WIDTH = 50

MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 10


def _print_separator(char='='):
    """Print a separator line for formatting using module width."""
    print(char * SEPARATOR_WIDTH)


def _print_label_value(label, value):
    """Print a label-value pair with consistent formatting."""
    print(f"{label:35}{value}")


def _print_title(title, width=SEPARATOR_WIDTH, sep_char='='):
    """Print a centered title with separator lines.

    The title is centered inside a line of length `width`. Surrounding lines
    composed of `sep_char` are printed above and below the title to match
    the existing visual style.
    """
    print(sep_char * width)
    print(title.center(width))
    print(sep_char * width)


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
        print()
        _print_separator()
        print("Checking key validity for key:")
        try: # Print the key matrices with justified elements, if fails, print using the built in print for arrays
            print(f"  [{key[0][0]:>3},{key[0][1]:>3}]")
            print(f"  [{key[1][0]:>3},{key[1][1]:>3}]")
        except Exception:
            print(f"  {key}")
        print("-" * 50)


        # size check
        size_ok = isinstance(key, list) and len(key) == 2 and isinstance(key[0], list) and len(key[0]) == 2 and len(key[1]) == 2
        _print_label_value("Matrix size:", "OK" if size_ok else "NOT VALID")
        if not size_ok:
            _print_separator()
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
        _print_label_value(f"Elements in range [0,{N-1}]:", "OK" if elements_ok else "NOT VALID")
        if not elements_ok:
            _print_separator()
            return False

        # determinant and gcd
        determinant = (key[0][0] * key[1][1] - key[0][1] * key[1][0]) % N
        _print_label_value("Determinant mod N:", determinant)
        gcd = math.gcd(determinant, N)
        _print_label_value("GCD(det, N):", gcd)
        invertible = gcd == 1
        _print_label_value("Key invertible:", "Yes" if invertible else "No")
        _print_separator()
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


def validate_input_string(s):
    """Validate input string against the plane space descriptor (letters a..z).

    - Input must be a non-empty string containing at least one alphabetic character.
    - Non-letter characters are ignored by the cipher, but we still require at least
      one alphabet character to proceed.

    Returns the cleaned lowercase string if valid, or None if invalid.
    """
    if not isinstance(s, str):
        return None
    
    if (len(s) < MIN_STRING_LENGTH or MAX_STRING_LENGTH < len(s)):
        return None
    
    cleaned = ''.join(ch.lower() for ch in s if ch.isalpha())
    return cleaned if len(cleaned) > 0 else None


def matrix_multiply(A, B):
    """Multiply matrices A (m x k) and B (k x n) and return m x n result.
    
    Performs standard matrix multiplication with dimension validation.
    
    Args:
        A (list[list[int]]): m x k matrix.
        B (list[list[int]]): k x n matrix.
    
    Returns:
        list[list[int]]: m x n result matrix.
    
    Raises:
        ValueError: If matrix dimensions are incompatible (cols of A != rows of B).
    """
    rows_A, cols_A = len(A), len(A[0])
    rows_B, cols_B = len(B), len(B[0])
    
    if cols_A != rows_B:
        raise ValueError("Incompatible matrix sizes for multiplication")
    
    result = [[0 for _ in range(cols_B)] for _ in range(rows_A)]
    for i in range(rows_A):
        for j in range(cols_B):
            result[i][j] = sum(A[i][k] * B[k][j] for k in range(cols_A))
    return result


def _encrypt_block(block, key, a, b, N):
    """Encrypt a 2-element block
    
    Performs: Y = (block * key + (a, b)) mod N
    
    Args:
        block (list[int]): 2-element block to encrypt.
        key (list[list[int]]): 2x2 encryption key matrix.
        a (int): First affine offset.
        b (int): Second affine offset.
        N (int): Modulus.
    
    Returns:
        list[int]: Encrypted 2-element block modulo N.
    """
    product = matrix_multiply([block], key)[0]
    return [(product[0] + a) % N, (product[1] + b) % N]


def _decrypt_block(block, key, a, b, N):
    """Decrypt a 2-element block using Hill cipher with affine subtraction.
    
    Performs: X = (block - (a, b)) * key_inverse mod N
    
    Args:
        block (list[int]): 2-element block to decrypt.
        key (list[list[int]]): 2x2 decryption key matrix (inverse of encryption key).
        a (int): First affine offset.
        b (int): Second affine offset.
        N (int): Modulus.
    
    Returns:
        list[int]: Decrypted 2-element block modulo N.
    """
    adjusted = [(block[0] - a) % N, (block[1] - b) % N]
    product = matrix_multiply([adjusted], key)[0]
    return [val % N for val in product]


def NameCipher_encryption(plaintext, first_encryption_key, second_encryption_key, a, b, N):
    """Encrypt plaintext using the two-stage NameCipher scheme.

    This function performs:
    1. Y = (X * K1 + (a,b)) mod N
    2. Z = (Y * K2 + (a,b)) mod N

    The function pads the input with '$' when plaintext length is odd.
    A padding marker is appended to indicate this.

    Args:
        plaintext (str): Input text to encrypt. Non-letters are ignored.
        first_encryption_key (list[list[int]]): First 2x2 encryption key K1.
        second_encryption_key (list[list[int]]): Second 2x2 encryption key K2.
        a (int): First affine offset value.
        b (int): Second affine offset value.
        N (int): Modulus.

    Returns:
        str: Ciphertext as a lowercase string (with '$' suffix if padding was used).
    """
    plaintext_ints = String_to_int(plaintext)
    needs_padding = len(plaintext_ints) % 2 != 0
    
    if needs_padding:
        plaintext_ints.append(PAD_NUM)

    # First encryption stage: Y = (X * K1 + (a,b)) mod N
    y_ints = []
    for i in range(0, len(plaintext_ints), 2):
        block = plaintext_ints[i:i+2]
        y_ints.extend(_encrypt_block(block, first_encryption_key, a, b, N))

    # Second encryption stage: Z = (Y * K2 + (a,b)) mod N
    z_ints = []
    for i in range(0, len(y_ints), 2):
        block = y_ints[i:i+2]
        z_ints.extend(_encrypt_block(block, second_encryption_key, a, b, N))

    ciphertext = int_to_string(z_ints, pad_char=PAD_CHAR, remove_padding=False)
    return ciphertext + PAD_CHAR if needs_padding else ciphertext


def NameCipher_decryption(ciphertext, decryption_key, second_decryption_key, a, b, N):
    """Decrypt ciphertext produced by NameCipher.

    Reverses the two-stage encryption. If ciphertext ends with PAD_CHAR,
    it indicates padding was used and is removed from the result.

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
    has_padding = len(ciphertext) > 0 and ciphertext[-1] == PAD_CHAR
    cipher_no_marker = ciphertext[:-1] if has_padding else ciphertext
    cipher_ints = String_to_int(cipher_no_marker)

    # Reverse second encryption stage: Y = (Z - (a,b)) * K2_inv
    y_ints = []
    for i in range(0, len(cipher_ints), 2):
        block = [cipher_ints[i], cipher_ints[i+1] if i+1 < len(cipher_ints) else PAD_NUM]
        y_ints.extend(_decrypt_block(block, second_decryption_key, a, b, N))

    # Reverse first encryption stage: X = (Y - (a,b)) * K1_inv
    x_ints = []
    for i in range(0, len(y_ints), 2):
        block = [y_ints[i], y_ints[i+1] if i+1 < len(y_ints) else PAD_NUM]
        x_ints.extend(_decrypt_block(block, decryption_key, a, b, N))

    plaintext = int_to_string(x_ints, pad_char=PAD_CHAR, remove_padding=False)
    return plaintext[:-1] if has_padding and len(plaintext) > 0 else plaintext

def _print_mapping(plaintext, ciphertext):
    """Print a mapping between plaintext letters and ciphertext letters.

    Returns 0 on success, -1 if lengths mismatch.
    """
    if len(plaintext) != len(ciphertext):
        print(f"The length of the cipher and plaintext is not the same.\nThe plaintext: {plaintext}\nThe ciphertext: {ciphertext}")
        return -1

    print()
    print("Mapping plaintext to ciphertext")
    for char_plain, char_cipher in zip(plaintext, ciphertext):
        print(f"{char_plain} => {char_cipher}")
    print()


# Exercise 2 - Iterative attack
def iterative_attack(plaintext, initial_cipher, first_encryption_key, second_encryption_key, a, b, N=26):
    """Perform iterative attack on ciphertext by repeatedly encrypting it.
    
    This attack exploits the cyclic nature of the NameCipher to decrypt ciphertext
    by repeatedly applying the encryption function until the plaintext is recovered.
    The padding marker ($) is properly handled to avoid expanding the ciphertext.
    
    Args:
        plaintext (str): Expected plaintext to match.
        initial_cipher (str): Starting ciphertext to encrypt iteratively.
        first_encryption_key (list[list[int]]): First 2x2 encryption key.
        second_encryption_key (list[list[int]]): Second 2x2 encryption key.
        a (int): First affine offset.
        b (int): Second affine offset.
        N (int, optional): Modulus. Defaults to 26.
    
    Prints:
        Number of iterations needed and final result.
    """
    iterative_attack_iterations = 0
    slice_for_odd_length = len(initial_cipher) - 2
    # Remove padding marker to get the actual text to encrypt
    initial_cipher_no_marking = initial_cipher[:slice_for_odd_length] if initial_cipher.endswith(PAD_CHAR) else initial_cipher
    cipher_after_iterative_attack = initial_cipher_no_marking
        
    while (True):
        # Keep the previous cipher so it can be used later to print the correlation between the letters
        prev_cipher = cipher_after_iterative_attack
        
        iterative_attack_iterations += 1
        cipher_after_iterative_attack = NameCipher_encryption(cipher_after_iterative_attack, first_encryption_key, second_encryption_key, a, b, N)
        # For an Odd cipher, remove the padding marker to continue iterating
        cipher_after_iterative_attack = cipher_after_iterative_attack[:slice_for_odd_length] if cipher_after_iterative_attack.endswith(PAD_CHAR) else cipher_after_iterative_attack
        
        # Found the plaintext from the cipher        
        if (initial_cipher_no_marking == cipher_after_iterative_attack):
            _print_mapping(prev_cipher, initial_cipher_no_marking)
            break
    
    _print_separator()
    _print_label_value("\nPlaintext:", plaintext)
    _print_label_value("Initial cipher:", initial_cipher)
    print("First encryption key:")
    print_2x2_matrix(first_encryption_key)
    print("Second encryption key:")
    print_2x2_matrix(second_encryption_key)
    _print_label_value("Cipher after iterative attack:", cipher_after_iterative_attack)
    _print_label_value("Iterations:", iterative_attack_iterations) 
    print()
    _print_separator()

    
def print_2x2_matrix(matrix):
    """Print a 2x2 matrix in formatted style with validation.
    
    Args:
        matrix (list[list[int]]): 2x2 matrix to print.
    
    Raises:
        ValueError: If matrix is not 2x2 or contains non-numeric elements.
    """
    # Check that matrix is a list of 2 elements
    if not isinstance(matrix, list) or len(matrix) != 2:
        raise ValueError("Matrix must be a 2×2 list of lists.")

    # Check that each row is a list of size 2
    for row in matrix:
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError("Matrix must be 2×2.")

    # Check that every element is a number
    for row in matrix:
        for element in row:
            if not isinstance(element, (int, float)):
                raise ValueError("Matrix elements must be numeric.")

    # If everything is OK → print formatted
    print(f"  [{matrix[0][0]:>3},{matrix[0][1]:>3}]")
    print(f"  [{matrix[1][0]:>3},{matrix[1][1]:>3}]")
        
def main():
    """Demonstrate NameCipher encryption and decryption."""
    N = 26
    a = 17
    b = 24


    # Encryption keys
    first_encryption_key = [[17, 14], [0, 3]]
    second_encryption_key = [[5, 14], [14, 17]]

    # Validate keys
    if not (is_key_valid(first_encryption_key, N) and is_key_valid(second_encryption_key, N)):
        print("One or more keys are invalid. Exiting.")
        return 1

    # Compute decryption keys (modular inverses)
    decryption_key = inverse_2x2_matrix(first_encryption_key, N)
    second_decryption_key = inverse_2x2_matrix(second_encryption_key, N)

    while (True):
        plaintext = input("\nInsert plaintext, alphabetic characters only\nexit or quit to exit\n")
        plaintext = validate_input_string(plaintext) # Returns a lower case string without any letters that are non-alphabetic letters
        
        # Validate input
        if (plaintext == None):
            print("\nPlease insert a string with only letters from the English alphabet... [a-z] [A-Z]\n"
                  "The string has to be between 4 to 10 letters")
            continue # Skip to the next iteration so another input is get inserted instead of the current one
        
        # Finish runtime due to user input
        if (plaintext.lower() in EXIT_COMMANDS):
            print("Finishing Execution...")
            break
    
        # Encryption
        cipher = NameCipher_encryption(plaintext, first_encryption_key, second_encryption_key, a, b, N)
        
        _print_title("ENCRYPTION")
        _print_label_value("\nPlaintext:", plaintext)
        print("First encryption key:")
        print_2x2_matrix(first_encryption_key)
        print("Second encryption key:")
        print_2x2_matrix(second_encryption_key)
        _print_label_value("Ciphertext:", cipher)
        print()

        # Decryption
        decrypted = NameCipher_decryption(cipher, decryption_key, second_decryption_key, a, b, N)
        
        _print_title("DECRYPTION")
        _print_label_value("\nCiphertext:", cipher)
        print("First decryption key:")
        print_2x2_matrix(decryption_key)
        print("Second decryption key:")
        print_2x2_matrix(second_decryption_key)
        _print_label_value("Decrypted:", decrypted)
        _print_label_value("Match:", "YES" if decrypted == plaintext else "NO")
        print()
        
         # 2nd exercise: Iterative Attack
        _print_title("ITERATIVE ATTACK")
        iterative_attack(plaintext, cipher, first_encryption_key, second_encryption_key, a, b, N)
        print()
        

if __name__ == "__main__":
    main()