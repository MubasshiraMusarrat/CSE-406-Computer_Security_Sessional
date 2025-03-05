from BitVector import *
import numpy as np
import secrets
import time
import base64
import importlib
bv = importlib.import_module('1905088_f1')
files = importlib.import_module('1905088_f2')

def string_to_matrix(string):
    hex_val = []
    for char in string:
        if(char == ''):
            hex_val.append('00')
        else:
            hex_val.append(hex(ord(char))[2:])
    return np.reshape(hex_val, (4,4))

def round_constant(round):
    if(round == 1):
        return BitVector(hexstring="01")
    elif (round > 1 & round_constant(round-1).intValue() < 0x80):
        return round_constant(round-1).gf_multiply_modular(BitVector(hexstring="02"), bv.AES_modulus, 8)
    else:
        return round_constant(round-1).gf_multiply_modular(BitVector(hexstring="02"), bv.AES_modulus, 8).gf_xor(BitVector(hexstring="11b"), 8)

def g(key, round):
    key = np.roll(key, -1)
    key = [hex(bv.Sbox[int(i,16)])[2:] for i in key]
    key[0] = hex(int(key[0],16) ^ round_constant(round).intValue())[2:]
    #print("Key:", key)
    return key

def XOR (a, b):
    return [hex(int(a[i],16) ^ int(b[i],16))[2:] for i in range(len(a))]

def generate_round_key(mat, round):
    generated_key = g(mat[3], round)
    #print(generated_key)
    w = XOR(mat[0], generated_key)
    round_key = [w]
    for i in range(1,4):
        w = XOR(w, mat[i])
        #print(w)
        round_key.append(w)
    round_key = np.reshape(round_key, (4,4))
    #print(round_key)
    return round_key

def XOR_matrix(mat1, mat2):
    return np.reshape([XOR(mat1[i], mat2[i]) for i in range(len(mat1))], (4,4))

def Mix_Column(mat1, mat2):
    result = []
    for i in range(len(mat1)):
        row = []
        for j in range(len(mat1[i])):
            product = BitVector(hexstring="00")
            for k in range(len(mat1[i])):
                bv1 = mat1[i][k]
                bv2 = BitVector(hexstring=mat2[k][j])
                product = product ^ (bv1.gf_multiply_modular(bv2, bv.AES_modulus, 8))
            row.append(hex(product.intValue())[2:])
        result.append(row)
    #print(result)
    return np.reshape(result, (4,4))

def Inv_Mix_Column(mat1, mat2):
    result = []
    for i in range(len(mat1)):
        row = []
        for j in range(len(mat1[i])):
            product = BitVector(hexstring="00")
            for k in range(len(mat1[i])):
                bv1 = mat1[i][k]
                bv2 = BitVector(hexstring=mat2[k][j])
                product = product ^ (bv1.gf_multiply_modular(bv2, bv.AES_modulus, 8))
            row.append(hex(product.intValue())[2:])
        result.append(row)
    #print(result)
    return np.reshape(result, (4,4))

def generate_all_round_keys(key_matrix):
    keys = []
    keys.append(key_matrix)
    #print(keys[0])
    for i in range(1,11):
        keys.append(generate_round_key(keys[i-1], i))
        #print(keys[i])
    keys = np.array(keys)
    return keys

def pad_split(plainText, length):
    row_num = (len(plainText)+length-1)//length
    plainText = np.array(list(plainText.ljust(row_num*length, ' ')))
    plainTextBlocks = np.reshape(plainText, (row_num, length))
    #print(plainTextBlocks)
    return plainTextBlocks

def pad_pkcs7(plainText, block_size):
    pad_value = block_size - (len(plainText) % block_size)
    plainText += chr(pad_value) * pad_value
    plainText = np.array(list(plainText))
    plainTextBlocks = np.reshape(plainText, (len(plainText)//block_size, block_size))
    return plainTextBlocks

def unpad_pkcs7(plainText):
    pad_value = ord(plainText[-1])
    return plainText[:-pad_value]

def block_encryption(keys, state_matrix):
    state_matrix = XOR_matrix(state_matrix.T, keys[0].T)
    #print(state_matrix)

    Rounds = len(keys)
    for round in range(1, Rounds):
        #print("Round", round, ":")
        for i in range(len(state_matrix)):
            state_matrix[i] = [hex(bv.Sbox[int(j, 16)])[2:] for j in state_matrix[i]]
            state_matrix[i] = np.roll(state_matrix[i], -i)
        #print(state_matrix)

        if round != Rounds - 1:
            state_matrix = Mix_Column(bv.Mixer, state_matrix)
        #print(state_matrix)

        state_matrix = XOR_matrix(state_matrix, keys[round].T)
        #print(state_matrix)
    return state_matrix.T

def block_decryption(keys, state_matrix):
    state_matrix = XOR_matrix(state_matrix,keys[len(keys)-1].T)

    Rounds = len(keys)
    for round in range(1,Rounds):
        for i in range(len(state_matrix)):
            state_matrix[i] = np.roll(state_matrix[i], i)
            state_matrix[i] = [hex(bv.InvSbox[int(j,16)])[2:] for j in state_matrix[i]]

        state_matrix = XOR_matrix(state_matrix, keys[len(keys)-1-round].T)

        if(round != Rounds-1):
            state_matrix = Inv_Mix_Column(bv.InvMixer,state_matrix)
    return state_matrix.T

def CBC_enc(keys, plain_text_matrices):
    cipher_matrices = []
    iv = secrets.token_bytes(16)
    iv = np.reshape(np.array([hex(byte)[2:] for byte in iv]), (4, 4))
    cipher_matrices.append(iv)
    #print(iv)

    for i in range(len(plain_text_matrices)):
        cipher_matrices.append(block_encryption(keys, XOR_matrix(plain_text_matrices[i], cipher_matrices[i])))
    #print(np.array(cipher_matrices))
    return np.array(cipher_matrices)

def CBC_dec(keys, cipherTextMatrices):
    deciphered_matrices = []
    # iv = cipherTextMatrices[0]
    for i in range(1,len(cipherTextMatrices)):
        deciphered_matrices.append(XOR_matrix(cipherTextMatrices[i-1], block_decryption(keys, cipherTextMatrices[i].T))) 
    # print("Deciphered:", np.array(deciphered_matrices))
    return np.array(deciphered_matrices)

def encrypt_CBC(encryption_key, plain_text):
    encryption_key = encryption_key.strip()[:16].ljust(16, ' ')
    print("\nKey: ")
    print("In ASCII: ", encryption_key)

    key_matrix = string_to_matrix(encryption_key)
    # print(key_matrix)
    print("In Hex: ",end="")
    print(*key_matrix.flatten(), sep=" ")

    key_generation_start = time.time()
    keys = generate_all_round_keys(key_matrix)
    # print(keys)
    key_generation_end = time.time()
    key_generation_time = key_generation_end - key_generation_start

    # plain_text = "Never Gonna Give you up"
    print("\nPlain Text: ")
    print("In ASCII: ", plain_text)

    # plain_text_blocks = pad_split(plain_text, 16)
    plain_text_blocks = pad_pkcs7(plain_text, 16)
    #print(plain_text_blocks)

    plain_text_matrices = [string_to_matrix(plain_text_blocks[i]) for i in range(len(plain_text_blocks))]
    plain_text_matrices = np.array(plain_text_matrices)
    # print(plain_text_matrices)
    print("In Hex: ",end="")
    print(*plain_text_matrices.flatten(), sep=" ")

    encryption_start = time.time()
    cipher_matrices = CBC_enc(keys, plain_text_matrices) 
    # print(cipher_matrices)
    encryption_end = time.time()
    encryption_time = encryption_end - encryption_start

    print("\nCiphered Text: ")
    print("In Hex: ",end="")
    print(*cipher_matrices.flatten(), sep=" ")

    ascii_cipher = ''.join([chr(int(cipher_matrices.flatten()[i],16)) for i in range(len(cipher_matrices.flatten()))])
    return ascii_cipher, key_generation_time, encryption_time

def decrypt_CBC(decryption_key, cipher_text):
    decryption_key = decryption_key.strip()[:16].ljust(16, ' ')
    #print("Decryption Key:", decryption_key)
    key_matrix = string_to_matrix(decryption_key)
    #print("Decipher Key Matrix:", key_matrix)

    keys = generate_all_round_keys(key_matrix)
    # print("Deciphered Keys: ",keys)

    #print("Cipher Text:", cipher_text)
        
    cipher_text_block = [cipher_text[i:i+16] for i in range(0, len(cipher_text), 16)]

    cipher_text_matrices = [string_to_matrix(i) for i in cipher_text_block]
    cipher_text_matrices = np.array(cipher_text_matrices)
    # print("Cipher Text Matrices:", cipher_text_matrices)

    decryption_start = time.time()
    deciphered_text_matrices = CBC_dec(keys, cipher_text_matrices)
    # print("Deciphered: ", deciphered_text_matrices)
    decryption_end = time.time()
    decryption_time = decryption_end - decryption_start

    print("\nDeciphered Text: ")
    print("In Hex: ",end="")
    print(*deciphered_text_matrices.flatten(), sep=" ")

    ascii_decipher = ''.join([chr(int(deciphered_text_matrices.flatten()[i],16)) for i in range(len(deciphered_text_matrices.flatten()))])
    # ascii_decipher = ascii_decipher.rstrip(' ')
    ascii_decipher = unpad_pkcs7(ascii_decipher)

    return ascii_decipher, decryption_time

def encrypt_CTR(encryption_key,plain_text):
    encryption_key = encryption_key.strip()[:16].ljust(16, ' ')
    print("\nKey: ")
    print("In ASCII: ", encryption_key)

    key_matrix = string_to_matrix(encryption_key)
    # print(key_matrix)
    print("In Hex: ",end="")
    print(*key_matrix.flatten(), sep=" ")

    key_generation_start = time.time()
    keys = generate_all_round_keys(key_matrix)
    # print(keys)
    key_generation_end = time.time()
    key_generation_time = key_generation_end - key_generation_start

    # plain_text = "Never Gonna Give you up"
    print("\nPlain Text: ")
    print("In ASCII: ", plain_text)

    print("In Hex: ",end="")
    hex_plain_text = ' '.join([hex(ord(char))[2:] for char in plain_text])
    print(hex_plain_text)

    counter = 0
    nonce = secrets.token_bytes(15)
    nonce_base64 = base64.b64encode(nonce).decode('utf-8')
    # print("length: ",len(nonce_base64))
    cipher_text = ""
    cipher_text += nonce_base64
    nonce = bin(int.from_bytes(nonce, byteorder='big'))[2:].zfill(120)

    block_num = (len(plain_text)+15)//16
    plaintext_blocks = [plain_text[i * 16: (i + 1) * 16] for i in range(block_num)]

    for i in range(block_num):
        text = nonce + bin(counter)[2:].zfill(8)
        text = ''.join([chr(int(text[i:i + 8], 2)) for i in range(0, len(text), 8)])
        # print("Text: ", text)
        encrypton_start = time.time()
        encrypted_nonce = block_encryption(keys, string_to_matrix(text))
        encryption_end = time.time()
        encryption_time = encryption_end - encrypton_start
        encrypted_nonce = ''.join([chr(int(encrypted_nonce.flatten()[i],16)) for i in range(len(encrypted_nonce.flatten()))])
        # print("Encrypted Nonce: ", encrypted_nonce)
        if(len(plaintext_blocks[i]) < 16):
            encrypted_nonce = encrypted_nonce[:len(plaintext_blocks[i])]
        cipher_text += ''.join([chr(ord(plaintext_blocks[i][j]) ^ ord(encrypted_nonce[j])) for j in range(len(plaintext_blocks[i]))])
        counter += 1

    print("\nCiphered Text: ")
    print("In Hex: ",end="")
    hex_cipher_text = ' '.join([hex(ord(char))[2:] for char in cipher_text])
    print(hex_cipher_text)

    return cipher_text, key_generation_time, encryption_time

def decrypt_CTR(decryption_key, cipher_text):
    decryption_key = decryption_key.strip()[:16].ljust(16, ' ')
    #print("Decryption Key:", decryption_key)
    key_matrix = string_to_matrix(decryption_key)
    #print("Decipher Key Matrix:", key_matrix)

    keys = generate_all_round_keys(key_matrix)
    # print("Deciphered Keys: ",keys)

    counter = 0
    nonce = base64.b64decode(cipher_text[:20])
    cipher_text = cipher_text[20:]
    nonce = bin(int.from_bytes(nonce, byteorder='big'))[2:].zfill(120)

    block_num = (len(cipher_text)+15)//16
    cipher_text_blocks = [cipher_text[i * 16: (i + 1) * 16] for i in range(block_num)]

    deciphered_text = ""
    for i in range(block_num):
        text = nonce + bin(counter)[2:].zfill(8)
        text = ''.join([chr(int(text[i:i + 8], 2)) for i in range(0, len(text), 8)])
        encrypted_nonce = block_encryption(keys, string_to_matrix(text))
        encrypted_nonce = ''.join([chr(int(encrypted_nonce.flatten()[i],16)) for i in range(len(encrypted_nonce.flatten()))])
        if(len(cipher_text_blocks[i]) < 16):
            encrypted_nonce = encrypted_nonce[:len(cipher_text_blocks[i])]
        decryption_start = time.time()
        deciphered_text += ''.join([chr(ord(cipher_text_blocks[i][j]) ^ ord(encrypted_nonce[j])) for j in range(len(cipher_text_blocks[i]))])
        decryption_end = time.time()
        decryption_time = decryption_end - decryption_start
        counter += 1
    
    print("\nDeciphered Text: ")
    print("In Hex: ",end="")
    hex_deciphered_text = ' '.join([hex(ord(char))[2:] for char in deciphered_text])
    print(hex_deciphered_text)

    return deciphered_text, decryption_time

def main():
    # encryption_key = input("Enter the encryption key: ").strip()[:16]
    encryption_key = "BUET CSE19 Batch"
    # plain_text = input("Enter the plain text: ")
    plain_text = "Never Gonna Give you up"
    # plain_text = files.file_to_string("1905088_f7.jpg")
    cipher_text, key_generation_time, encryption_time = encrypt_CBC(encryption_key, plain_text)
    # cipher_text, key_generation_time, encryption_time = encrypt_CTR(encryption_key, plain_text)
    print("In ASCII: ", cipher_text)

    decryption_key = encryption_key
    ascii_decipher, decryption_time = decrypt_CBC(decryption_key, cipher_text)
    # ascii_decipher, decryption_time = decrypt_CTR(decryption_key, cipher_text)
    print("In ASCII: ", ascii_decipher)
    # files.string_to_file(ascii_decipher, "out.jpg")

    print("\nExecution Time Details: ")
    print("Key Schedule Time: ", key_generation_time, "s")
    print("Encryption Time: ", encryption_time, "s")
    print("Decryption Time: ", decryption_time, "seconds")

if __name__ == "__main__":
    main()