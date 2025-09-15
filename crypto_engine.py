import magiccube
from magiccube import Cube as mCube
from rubik.cube import Cube as rCube
from helper import str_to_perm_with_len, perm_to_str_with_len
from magiccube import BasicSolver


# cube = mCube(3, "YYYYYYYYYRRRRRRRRRGGGGGGGGGOOOOOOOOOBBBBBBBBBWWWWWWWWW")

# print(cube)

# cube.scramble()

# print(cube)

# history = cube.reverse_history() 
# reverse = " ".join([str(i) for i in history])

# cube.rotate(reverse)

# print(cube)

# copy_cube = cube.get()
# copy_cube = mCube(3, str(copy_cube))
# print(copy_cube)


class CryptoCube:
    def __init__(self, key_cube: mCube):
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

    def encrypt(self, plaintext: str) -> str:
        """
        

        Input: plaintext string
        Output: ciphertext encoded as a permutatuion of 48 symbols
        """
        permutation = str_to_perm_with_len(plaintext)
            #insert middles in indexes 4, 22, 25, 28, 31, 49
        for i in (4,22,25,28,31,49):
            permutation.insert(i, '$')

        permutation = "".join(permutation)

        random_cube = mCube(3, str(self.key_cube.get()))

        random_cube.scramble()
        perm_cube = rCube(permutation)

        A_moves = " ".join([str(i) for i in random_cube.history()])

        solver = BasicSolver(random_cube)
        solver.solve()

        encrypt_moves = " ".join([str(i) for i in random_cube.history()])
        encrypt_moves = encrypt_moves.replace("'", "i")
        encrypt_moves = encrypt_moves[len(A_moves):]

        perm_cube.sequence(encrypt_moves)
        ciphertext = perm_cube.flat_str()
        ciphertext = ciphertext.replace("$", "")


        return A_moves, ciphertext
        


        # # we need 
        # 1. A_moves
        # 2. B_moves
        # 3. perm Cube
        
        ...


    def decrypt(self, A_moves: str, ciphertext: str) -> str:
        key_cube = mCube(3, str(self.key_cube.get()))
        permutation = list(ciphertext)
        for i in (4,22,25,28,31,49):
            permutation.insert(i, '$')

        permutation = "".join(permutation)
        perm_cube = rCube(permutation)

        solver = BasicSolver(key_cube)
        key_cube.rotate(A_moves)
        solver.solve()

        decrypt_moves = " ".join([str(i) for i in key_cube.history()])
        decrypt_moves = decrypt_moves.replace("'", "i")
        decrypt_moves = decrypt_moves[len(A_moves):]
        decrypt_moves = self.reverse_moves(decrypt_moves.split(" "))
        decrypt_moves = " ".join(decrypt_moves)

        perm_cube.sequence(decrypt_moves)
        plaintext = perm_cube.flat_str().replace("$", "")
        plaintext = perm_to_str_with_len(list(plaintext))

        return plaintext


def main():
    key_cube = mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW")

    cryptic_cube = CryptoCube(key_cube)

    A_moves, ciphertext = cryptic_cube.encrypt("hide message ")   # <= 25 bytes payload

    print(A_moves,ciphertext)   # <= 25 bytes payload

    plaintext = cryptic_cube.decrypt(A_moves, ciphertext)
    print(plaintext)   # <= 25 bytes payload


if __name__ == "__main__":
    main()

