import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from crypto_engine import CryptoCube
from magiccube import Cube as mCube

from datetime import datetime

from logger import log_to_file

from typing import List, Union


def crptocube_wrapper(pt, keys:Union[List[mCube], None] = None):
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    KEYS1 = keys if keys else KEYS1

    cipher = CryptoCube(KEYS1,mode="bytes", whitten=False)
    ct, _ = cipher.encrypt(pt)
    if len(pt) == 54:
        ct = ct[:-1]
    return ct


def AES_wrapper(pt):
    key = os.urandom(32)
    aes_cipher = Cipher(algorithms.AES(key),modes.CTR(b"abdsjekrlsmjfvjs"))
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(pt) + encryptor.finalize()

    return ciphertext

def log_test(result, folder):
    today = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"{today}.json"
    path = f"{folder}/{file_name}"
    log_to_file(path, result)
    


