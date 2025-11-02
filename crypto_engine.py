import magiccube
from magiccube import Cube as mCube
from rubik.cube import Cube as rCube
from helper import str_to_perm_with_len, perm_to_str_with_len
from helper import int_to_perm, perm_to_int, byte_to_perm, perm_to_byte
from magiccube import BasicSolver

from helper import SOLVED_CUBE_STR


class CryptoCube:
    def __init__(self, key_cube: mCube, mode="utf-8"):
        #mode tells the cipher what the expected plaintext and ciphertext is
        self.mode = mode
        self.key_cube = key_cube

    def reverse_moves(self, moves: list):
            '''For  rubik cube module only'''
            try:
                moves = list(moves)
            except TypeError:
                try:
                    moves = " ".join(moves)
                    moves = moves.split(" ")
                except TypeError:
                    raise ValueError("Moves must be a list or string.")
            inverse = []
            for move in reversed(moves):
                if move == "":
                    continue  # skip empty moves
                if move.endswith("i"):  # inverse move (like Ri → R)
                    inverse.append(move[:-1])  
                else:  # normal move (like R → Ri)
                    inverse.append(move + "i")  
            return inverse

    def encrypt(self, plaintext: str|int|bytes) -> str:
        """
        Input: plaintext string
        Output: ciphertext encoded as a permutatuion of 48 symbols
        """
        try:
            if self.mode == "bytes":
                permutation = byte_to_perm(plaintext)
            if self.mode == "int":
                permutation = int_to_perm(plaintext)
            if self.mode not in ("bytes", "int"):
                permutation = str_to_perm_with_len(plaintext, self.mode)
                
            for i in (4,22,25,28,31,49):
                #insert middles in indexes 4, 22, 25, 28, 31, 49
                permutation.insert(i, '$')
        except:
            raise ValueError("plaintext: {plaintext} is in the wrong format or mismatched modes")

        permutation = "".join(permutation)

        demo = rCube(SOLVED_CUBE_STR)

        random_cube = mCube(3, str(self.key_cube.get()))

        random_cube.scramble()
        perm_cube = rCube(permutation)


        A_moves = " ".join([str(i) for i in random_cube.history()]) # moves from key to IV

        solver = BasicSolver(random_cube) # From IV to Solved state
        solver.solve()

        encrypt_moves = " ".join([str(i) for i in random_cube.history()])
        encrypt_moves = encrypt_moves.replace("'", "i")
        encrypt_moves = encrypt_moves[len(A_moves):] # reverses moves

        demo.sequence(encrypt_moves)
    

        perm_cube.sequence(encrypt_moves)


        ciphertext = perm_cube.flat_str()
        ciphertext = ciphertext.replace("$", "")


        return A_moves, ciphertext

    def decrypt(self, A_moves: str, ciphertext: str) -> str|int|bytes:
        key_cube = mCube(3, str(self.key_cube.get()))
        permutation = list(ciphertext)
        for i in (4,22,25,28,31,49):
            permutation.insert(i, '$')

        permutation = "".join(permutation)
        perm_cube = rCube(permutation)

        demo = rCube(SOLVED_CUBE_STR)

        solver = BasicSolver(key_cube)
        key_cube.rotate(A_moves)
        solver.solve()

        decrypt_moves = " ".join([str(i) for i in key_cube.history()])
        decrypt_moves = decrypt_moves.replace("'", "i")
        decrypt_moves = decrypt_moves[len(A_moves):]
        decrypt_moves = self.reverse_moves(decrypt_moves.split(" "))
        decrypt_moves = " ".join(decrypt_moves)

        perm_cube.sequence(decrypt_moves)
        demo.sequence(decrypt_moves)


        plaintext = perm_cube.flat_str().replace("$", "")
        
        try:
            if self.mode == "bytes":
                plaintext = perm_to_byte(plaintext)
            if self.mode == "int":
                plaintext = perm_to_int(plaintext)
            if self.mode not in ("bytes", "int"):
                plaintext = perm_to_str_with_len(plaintext, self.mode)
        except:
            raise ValueError("plaintext: {plaintext} is in the wrong format or mismatched modes")

        return plaintext


def main():
    #sample test input
    key_cube = mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW")

    cryptic_cube = CryptoCube(key_cube)

    # A_moves, ciphertext = cryptic_cube.encrypt("hello")   # <= 25 bytes payload

    # print(A_moves,ciphertext)   # <= 25 bytes payload

    A_moves = "F D D F' F L U' F B' R F' F F B U D R' L F' D' F' B' B F' B' L U' R' D B' R' R F L L B R R D B B D B' U R' L' B' B F F'"
    ciphertext = "z4dxr8c5IH0j6abke7fCoi1pqALnK3EutGDmhgFyvBs9lJw2"

    plaintext = cryptic_cube.decrypt(A_moves, ciphertext)
    print(plaintext)   # <= 25 bytes payload

    


if __name__ == "__main__":
    main()

