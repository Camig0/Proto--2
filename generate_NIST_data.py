import os
from magiccube import Cube as mCube
from crypto_engine import CryptoCube
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def write_nist_bin(byte_string: bytes, filename: str = "data.bin") -> None:
    """
    Write a byte string to a binary file suitable for NIST SP 800-22.

    Args:
        byte_string (bytes): The data to write (ciphertext or other bytes).
        filename (str): Output .bin file name (default: data.bin).

    Returns:
        None
    """
    if not isinstance(byte_string, (bytes, bytearray)):
        raise TypeError("byte_string must be bytes or bytearray")

    with open(filename, "wb") as f:
        f.write(byte_string)

    print(f"Wrote {len(byte_string)} bytes ({len(byte_string) * 8:,} bits) to {filename}")

def crptocube_wrapper(pt):
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    cipher = CryptoCube(KEYS1,mode="bytes", whitten=False)
    ct, _ = cipher.encrypt_ctr(pt)
    return ct, None

def AES_wrapper(pt):
    key = os.urandom(32)
    aes_cipher = Cipher(algorithms.AES(key),modes.CTR(b"abdsjekrlsmjfvjs"))
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(pt) + encryptor.finalize()

    

    return ciphertext, None



if __name__ == "__main__":
    plaintext = os.urandom( 1024) #10MB


    ciphertext, _ = crptocube_wrapper(plaintext)

    write_nist_bin(ciphertext)