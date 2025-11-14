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

def is_key_valid(key):
    """
    Checks whether a key matrix

    Conditions checked:
    - `key` is a non-empty square matrix (list of lists).
    - All entries are integers in the range 0..25.
    - The determinant modulo 26 is invertible (i.e. gcd(det, 26) == 1).

    Returns True if valid, False otherwise.
    """
    try:
        print(
            f"\n====================================\n" 
            f"Checking key validity for key:\n"
            f"{key[0]}\n{key[1]}\n"
            f"====================================" 
        )
        
        # Demand a 2x2 matrix
        print("Check matrix size: ", end = '')
        if len(key) != 2 or len(key[0]) != 2:
            print("❌ size not valid")
            return False
        print("✅ OK")
        
        
        # Check if all of the inner elements are in the range of [0,25]
        print("Check each element size in the array: ", end = '')
        for row in key:
            for element in row:
                if (element < 0 or element > 25):
                    print(f"❌ found '{element}' which is not in [0,25]")
                    return False
        print("✅ OK")

        # compute determinant for the 2x2 matrix
        print(f"computing determinant: {key[0][0]} * {key[1][1]} - {key[0][1]} * {key[1][0]} ", end = '')
        determinant =  key[0][0] * key[1][1] - key[0][1] * key[1][0]
        determinant = determinant % 26 # Make sure the determinant is non-negative for the gcd function to work correctly
        print(f"= {determinant}")
        
        gcd = math.gcd(determinant, N)
        print(f"Calculating GCD({determinant}, {N}) = {gcd} ", end = '')
        if (gcd != 1):
            print("❌ GCD is {gcd} != 1 => key is not invertible => key is not valid")
        else:
            print("✅ OK, GCD = 1")
        
        print("====================================")

        
        # for the key to be valid we need gcd(key, N) = 1
        return math.gcd(determinant, N) == 1
    except Exception:
        return False

def inverse_2x2_matrix(matrix):
        determinant = (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26
        determinant_inv = pow(determinant, -1, 26)  # Modular multiplicative inverse
        inverse_matrix = [ 
            [(matrix[1][1] * determinant_inv) % 26, (-matrix[0][1] * determinant_inv) % 26],
            [(-matrix[1][0] * determinant_inv) % 26, (matrix[0][0] * determinant_inv) % 26]
        ]
        return inverse_matrix


def String_to_int(String):
    '''
    summary: convert a string to an int in the range of [0,25]
    '''
    result = [0] * len(String)
    
    for i in range(len(String)):
        result[i] = String[i].lower() - 'a'
    
    return result

def int_to_string(integer_array):
    '''
    summary: convert an int arr to a string form
    '''
    result = ""
    
    for integer in integer_array:
        result += chr(integer + 'a')

    return result

def matrix_multiply(A, B):
    """
    Performs matrix multiplication on two matrices, A and B.

    Args:
        A (list of lists): The first matrix (m x k).
        B (list of lists): The second matrix (k x n).

    Returns:
        list of lists: The resulting matrix (m x n), or None if matrices are incompatible.
    """
    # Get dimensions
    rows_A = len(A)
    cols_A = len(A[0])
    rows_B = len(B)
    cols_B = len(B[0])

    # Check for compatibility: columns of A must equal rows of B
    if cols_A != rows_B:
        print("Error: The number of columns in the first matrix must equal the number of rows in the second matrix.")
        return None

    # Initialize the result matrix C (rows_A x cols_B) with zeros
    C = [[0 for _ in range(cols_B)] for _ in range(rows_A)]

    # Perform the matrix multiplication
    # Iterate through rows of A
    for i in range(rows_A):
        # Iterate through columns of B
        for j in range(cols_B):
            # Iterate through columns of A (or rows of B)
            for k in range(cols_A):
                # The core multiplication and summation step
                C[i][j] += A[i][k] * B[k][j]

    return C



def  NameCipher_encryption (plaintext, key):
    '''
    The Encryption function defined by double encryption Z = EK2 (EK1(X)) is given in the following
    way:
    1. Y = EK1 (X) = (X *K1 + (a,b)) mod N
    2. Z = EK2 (Y *K2 + (a,b)) mod N
    '''
    
    # Road as 1st encryption key
    encryption_key = [[17, 14], 
                      [0, 3]]
    
    # Door as 2nd encryption key
    second_encryption_key = [[5,14],
                             [14,17]]

    
    plaintext_integer_array = String_to_int(plaintext)
    
    # 1. Y = EK1 (X) = (X *K1 + (a,b)) mod N
    Y_integer_array = [] 
    for i in range(len(plaintext), 2):
        block = [plaintext_integer_array[i], plaintext_integer_array[i + 1]] # (1,2)
        Y_integer_array += (block * encryption_key + [a, b]) % N 
    
    y_string_format = int_to_string(Y_integer_array)
    print(f"After first encryption {y_string_format}\n" +
          f"After first encryption as integers {y_string_format}")
    
    
    
    
    # y_integer_array to use
      
    # 2. Z = EK2 (Y *K2 + (a,b)) mod N
    Z_integer_array = []
    for i in range(len(Y_integer_array), 2):
        block = [Y_integer_array[i], Y_integer_array[i + 1]] # (1,2)
        Z_integer_array += key * (block * second_encryption_key + [a, b]) % N

    cipher_text = int_to_string(Z_integer_array)
    print(f"After second encryption {cipher_text}\n" +
          f"After second encryption as integers {Z_integer_array}")
    
    return cipher_text


def  NameCipher_decryption (plaintext, key):


    
    
    
    
    
    # -------------------------------------
    
    # Road as 1st decryption key (inverse of encryption key)
    decryption_key = [[3, 12], 
                      [0, 17]]
    
    # Door as 2nd decryption key (inverse of encryption key)
    second_decryption_key = [[17, 12],
                             [12, 5]]
    
    plaintext_integer_array = String_to_int(plaintext)
    
    # 1. Y = DK2 (Z - (a,b)) * K2_inv mod N
    Y_integer_array = [] 
    for i in range(len(plaintext), 2):
        block = [plaintext_integer_array[i], plaintext_integer_array[i + 1]] # (1,2)
        Y_integer_array += ((block - [a, b]) * second_decryption_key) % N 
    
    y_string_format = int_to_string(Y_integer_array)
    print(f"After first decryption {y_string_format}\n" +
          f"After first decryption as integers {Y_integer_array}")
    
    
    # 2. X = DK1 (Y - (a,b)) * K1_inv mod N
    X_integer_array = []
    for i in range(len(Y_integer_array), 2):
        block = [Y_integer_array[i], Y_integer_array[i + 1]] # (1,2)
        X_integer_array += ((block - [a, b]) * decryption_key) % N

    decrypted_text = int_to_string(X_integer_array)
    print(f"After second decryption {decrypted_text}\n" +
          f"After second decryption as integers {X_integer_array}")
    
    return decrypted_text

def main():
    global a, b, N
    global encryption_key, second_encryption_key
    global d
    
    
    N = 26
    a = 17 # 'R' for Roni 
    b = 24 # 'Y' for Yuval
    
    plaintext = "yuvalroni"
    
    # Road as 1st encryption key
    encryption_key = [[17, 14], 
                      [0, 3]]
    
    # Door as 2nd encryption key
    second_encryption_key = [[5,14],
                             [14,17]]
    
    # Check validity for encryption keys
    if not (is_key_valid(encryption_key) and is_key_valid(second_encryption_key)):
        print(
            "Both of the keys are not valid"
            "Finishing Execution"
            )
        return 1
         
    
    #! TODO!!!! VVV
    # Check validity for decryption keys

    


    
    
if __name__ == "__main__":
    main()