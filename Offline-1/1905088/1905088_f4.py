import random
from sympy import isprime
import random
import sys
import math
import time
import tabulate

def generate_random_prime(length):
    while True:
        num = random.getrandbits(length)
        if isprime(num):
            return num

def point_addition(point1, point2, p):
    s = ((point2[1] - point1[1]) * pow(point2[0] - point1[0], -1, p)) % p
    x = (s**2 - point1[0] - point2[0]) % p
    y = (s * (point1[0] - x) - point1[1]) % p
    return (x,y)

def point_doubling(point, p, a):
    # print("point = ", point)
    # print("p = ", p)
    # print("a = ", a)
    s = ((3 * point[0]**2 + a) * pow(2 * point[1], -1 , p)) % p
    x = (s**2 - 2 * point[0]) % p
    y = (s * (point[0] - x) - point[1]) % p
    # print("x = ", x)
    # print("y = ", y)
    return (x, y)

def scalar_multiply(d, point, p, a):
    # print("d = ", d)
    # print("point = ", point)
    # print("p = ", p)
    # print("a = ", a)
    d = bin(d)[2:]
    T = point
    for i in range(1, len(d)):
        T = point_doubling(T, p, a)
        if d[i] == '1':
            T = point_addition(T, point, p)
    return T
    
def generate_shared_parametrs(bit_length):
    p = generate_random_prime(bit_length)
    # print(p)

    # a = 2
    # b = 5
    # G = (3,4)
    a = random.randint(0,p-1)
    # print(a)

    while True:
        x = random.getrandbits(bit_length)
        y = random.getrandbits(bit_length)
        b = (y**2 - x**3 - a*x) % p
        if (4*a**3 + 27*b**2) % p != 0:
            break

    # # print(b)
    G = (x,y)
    # print(G)
    return p, a, b, G

def generate_shared_keys(p, G, a):
    # print("p = ", p)
    # print("a = ", a)
    # print("G = ", G)
    E = math.floor(p+1+2*math.sqrt(p))
    # print(E)

    K_private_A = random.randint(2,E-1)
    # print(K_private_A)
    K_public_A = scalar_multiply(K_private_A, G, p, a)
    # K_public_A = (K_public_A[0] % p, K_public_A[1] % p)
    # print(K_public_A)
    return K_private_A, K_public_A

def generate_secret_keys(K_private_A, K_public_B, p, a):
    K_secret_AB = scalar_multiply(K_private_A, K_public_B, p, a)
    # K_secret_AB = (K_secret_AB[0] % p, K_secret_AB[1] % p)
    # print(K_secret_AB)
    return K_secret_AB

def main():
    keys = [128, 192, 256]
    rows = []
    for i in range(len(keys)):
        timeA = 0
        timeB = 0
        timeR = 0
        for j in range(5):
            p, a, b, G = generate_shared_parametrs(keys[i])
            # print("p = ", p)
            # print("a = ", a)
            # print("b = ", b)
            # print("G = ", G)

            timeA_start = time.time()
            K_private_A, K_public_A = generate_shared_keys(p, G, a)
            # send K_public_A to B
            timeA_end = time.time()
            timeA += timeA_end - timeA_start

            timeB_start = time.time()
            K_private_B, K_public_B = generate_shared_keys(p, G, a)
            # send K_public_B to A
            timeB_end = time.time()
            timeB += timeB_end - timeB_start

            timeR_start = time.time()
            K_secret_AB = generate_secret_keys(K_private_A, K_public_B, p, a)
            # print(len(bin(K_secret_AB[0])[2:]))
            timeR_end = time.time()
            t = timeR_end - timeR_start
            timeR_start = time.time()
            K_secret_BA = generate_secret_keys(K_private_B, K_public_A, p, a)
            # if (K_secret_AB == K_secret_BA):
            #     print("Shared key is equal")
            # else:
            #     print("Shared key is not equal")
            timeR_end = time.time()
            t += timeR_end - timeR_start
            t /= 2
            timeR += t

        timeA /= 5
        timeB /= 5
        timeR /= 5
        rows.append([keys[i], timeA, timeB, timeR])
        # print(rows)

    print(tabulate.tabulate(rows, headers=["k", "A", "B", "Shared Key R"], tablefmt="github", floatfmt=".5f"))

if __name__ == "__main__":
    main()