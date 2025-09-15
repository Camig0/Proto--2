from crypto_engine import CryptoCube
from random import choice
import time
from magiccube import Cube as mCube

KEY_CUBE = mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW")

def main(): 
    
    def generate_test_case(symbols):
        return "".join(choice(symbols) for _ in range(24))
    mes = input("> ")
    cube = CryptoCube(KEY_CUBE)
    A_moves, encrypted = cube.encrypt(mes)
    print(encrypted)
    decrypt = cube.decrypt(A_moves, encrypted)
    print(decrypt)
        
if __name__ == "__main__":
    main()