import matplotlib.pyplot as plt
import os
from magiccube import Cube as mCube

from crypto_engine import CryptoCube

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def AES_wrapper(pt):
    key = os.urandom(32)
    aes_cipher = Cipher(algorithms.AES(key),modes.CTR(b"abdsjekrlsmjfvjs"))
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(pt) + encryptor.finalize()
    return ciphertext

#ciphertexts.append(base64.b64encode(ct).decode('utf-8'))

def generate_pt_ct(samples:int = 100):

    ciphertext = b""
    plaintext = b""
    for sample in range(samples):
        if sample % (samples/ 20) == 0:
            print(f"sample: {sample}/{samples}")
        pt = os.urandom(54)
        KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
        cipher = CryptoCube(KEYS1, mode="bytes")
        ct, _ = cipher.encrypt(pt)
        ciphertext += ct
        plaintext += pt
    return ciphertext, plaintext

def generate_pt_ct_AES(samples:int = 100):

    ciphertext = b""
    plaintext = b""
    for sample in range(samples):
        if sample % (samples/ 20) == 0:
            print(f"sample: {sample}/{samples}")
        pt = os.urandom(54)
        
        ct = AES_wrapper(pt)
        ciphertext += ct
        plaintext += pt
    return ciphertext, plaintext




def blocks(data, size):
    for i in range(0, len(data), size):
        yield data[i:i+size]

def block_int(b):
    return int.from_bytes(b, "big")

def scatter_blocks(plaintext, ciphertext, block_size=54):
    xs = []
    ys = []

    for p, c in zip(blocks(plaintext, block_size),
                    blocks(ciphertext, block_size)):

        if len(p) < block_size:
            break  # ignore last partial block

        xs.append(block_int(p))
        ys.append(block_int(c))



    plt.scatter(xs, ys, s=2)
    plt.xlabel("Plaintext block (big int)")
    plt.ylabel("Ciphertext block (big int)")
    plt.title("Plaintext → Ciphertext Block Scatter")
    plt.yscale('log')
    plt.xscale('log')
    plt.show()

if __name__ == "__main__":
    ciphertext, plaintext = generate_pt_ct_AES(100000)
    scatter_blocks(plaintext,ciphertext)