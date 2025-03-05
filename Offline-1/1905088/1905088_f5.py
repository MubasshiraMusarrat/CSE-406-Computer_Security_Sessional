import socket
import pickle
import importlib

files = importlib.import_module('1905088_f2')
aes = importlib.import_module('1905088_f3')
ECDH = importlib.import_module('1905088_f4')

PORT = 12345

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('localhost', PORT))

s.listen(5)

while True:
    print('Waiting for Bob')
    connect, address = s.accept()
    print('Bob Connected!')

    p, a, b, G = ECDH.generate_shared_parametrs(128)
    print("sending parameters...")
    data = [p, a, b, G]
    data=pickle.dumps(data)
    connect.send(data)

    K_private_A, K_public_A = ECDH.generate_shared_keys(p, G, a)
    # print(K_private_A)
    print("Sending Public Key...")
    connect.send(pickle.dumps(K_public_A))

    print("Waiting for Public Key...")
    K_public_B = pickle.loads(connect.recv(1024))
    print("Received Public Key...")
    # print(K_public_B)

    K_secret_AB = ECDH.generate_secret_keys(K_private_A, K_public_B, p, a)
    print(K_secret_AB)

    plaintext = "Never Gonna Give you up"
    # plaintext = files.file_to_string("apple.jpg")
    cipher_text  = aes.encrypt_CBC(str(K_secret_AB[0]), plaintext)[0]
    # cipher_text  = aes.encrypt_CTR(str(K_secret_AB[0]), plaintext)[0]
    print("In ASCII: ",cipher_text)

    print("\nSending Cipher Text...")
    connect.send(pickle.dumps(cipher_text))

    connect.close()
    break

