import socket
import pickle
import importlib

files = importlib.import_module('1905088_f2')
aes = importlib.import_module('1905088_f3')
ECDH = importlib.import_module('1905088_f4')


PORT = 12345

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as err:
    print("socket creation failed with error %s" % (err))

s.connect(('localhost', PORT))
print('Connected with Alice!')

print('Waiting for keys')
ECDHParams = pickle.loads(s.recv(1024))
print('Received keys')
# print(ECDHParams)

print('Waiting for public key')
K_public_A = pickle.loads(s.recv(1024))
# print(K_public_A)
print('Received public key')

K_private_B, K_public_B = ECDH.generate_shared_keys(ECDHParams[0], ECDHParams[3], ECDHParams[1])
# print(K_private_B)

print('Sending public key')
s.send(pickle.dumps(K_public_B))

K_secret_BA = ECDH.generate_secret_keys(K_private_B, K_public_A, ECDHParams[0], ECDHParams[1])
print(K_secret_BA)

print('Waiting for cipher text')
cipher_text = pickle.loads(s.recv(100*1024*1024))
print('Received cipher text')

deciphered_text = aes.decrypt_CBC(str(K_secret_BA[0]), cipher_text)[0]
# deciphered_text = aes.decrypt_CTR(str(K_secret_BA[0]), cipher_text)[0]
print("In ASCII: ", deciphered_text)

# files.string_to_file(deciphered_text, "out.jpg")
