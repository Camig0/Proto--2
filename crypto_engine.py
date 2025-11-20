from blake3 import blake3

import os

import magiccube
from magiccube import Cube as mCube
from rubik.cube import Cube as rCube

from helper import str_to_perm_with_len, perm_to_str_with_len, int_to_perm, perm_to_int, byte_to_perm, perm_to_byte
from helper import seeded_random_cube, get_solve_moves, serialize, deserialize

from magiccube import BasicSolver

from helper import SOLVED_CUBE_STR

def encrypt_block(
            key:str,
            block_data: bytes,
            IV:bytes|None=None,
            block:int=0,
            mode:str="bytes"
            ) -> str:
    from magiccube import Cube as mCube
    from rubik.cube import Cube as rCube # idk why imports are needed

    key_cube = mCube(3,key)

    cipher = CryptoCube(key_cube, mode="bytes")
    
    ciphertext, _ = cipher.encrypt(block_data, IV, block)

    return (block, ciphertext)

    
def decrypt_block( key:str, blockdata: str, IV:bytes,
            block:int=0, mode:str="bytes"
            ) -> str|int|bytes:
    from magiccube import Cube as mCube
    from rubik.cube import Cube as rCube # idk why imports are needed

    key_cube = mCube(3,key)

    cipher = CryptoCube(key_cube, mode="bytes")
    
    plaintext, _ = cipher.decrypt(blockdata, IV, block)

    return (block, plaintext)



class CryptoCube:
    def __init__(self, key_cube: mCube, mode="utf-8"):
        #mode tells the cipher what the expected plaintext and ciphertext is
        self.mode = mode
        self.key_cube = key_cube
        self.BLOCK_SIZE = 25

    def reverse_moves(self, moves: list):
            '''rCube notation compatability only'''
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

    def PRF(self, key, context, purpose):
        hasher = blake3()
        hasher.update(key.encode("utf-8"))
        hasher.update(context)
        hasher.update(purpose.encode("utf-8"))
        return hasher.digest()
        
    def cube_XOR(self,a:rCube, b:mCube)->rCube: #untested
        """XC: (a,b)-> c
        where b is the keystream"""
        transform = get_solve_moves(b,True)
        a.sequence(transform)
        return rCube(a.flat_str())


    def inverse_cube_XOR(self, c:rCube, b:mCube)->rCube: #untested
        """~XC: (c,b)-> a
        where b is the keystream"""
        transform = " ".join(self.reverse_moves(get_solve_moves(b, True).split(" "))) # rCube notation in string form
        c.sequence(transform)
        return rCube(c.flat_str())

# TODO: rewrite encrypt + decrypt of single block to module level
# TODO: write workers for parallel processign

    def encrypt(self,
                plaintext: str|int|bytes,
                IV:bytes|None=None,
                block:int=0
                ) -> str:
        """
        Input: plaintext string
        Output: ciphertext encoded as a permutatuion of 48 symbols
        """
        try: # FOR bytes int and character codec compatability
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

        if not IV: #if IV == None generate an IV, used when doing simple encrypt of just one block
            IV = os.urandom(16) # Nonce

        #clone the key
        key_cube = mCube(3, str(self.key_cube.get())) # color-only cube 
        # initializes as keycube then scrambles 
        # scramble sequence is moves A
        plain_cube = rCube(permutation) #plain cube

        # PRF using BLAKE3 to get cube

        seed = self.PRF(key_cube.get(), IV + block.to_bytes(4, "big"), "keystream") #uses blake3

        inter_cube = seeded_random_cube(seed) #untested output

        # apply cube XOR on plaincube x intercube --> ciphercube

        cipher_cube = self.cube_XOR(plain_cube, inter_cube)

        ciphertext = cipher_cube.flat_str().replace("$", "") # flatten cipher cube and remove filler symbols ($)
        

        return ciphertext, IV # ciphertext + flattened IV

    def decrypt(self, ciphertext: str, IV:bytes,
                block:int=0
                ) -> str|int|bytes:
        key_cube = mCube(3, str(self.key_cube.get()))
        permutation = list(ciphertext)
        for i in (4,22,25,28,31,49):
            permutation.insert(i, '$')

        permutation = "".join(permutation)
        cipher_cube = rCube(permutation) # ciphercube

         # Reconstruct inter_cube using PRF using BLAKE3

        seed = self.PRF(key_cube.get(), IV + block.to_bytes(4, "big"), "keystream")
        # print("decryption seed",seed)

        inter_cube = seeded_random_cube(seed)

        # print(inter_cube)

        # Apply cube reverse XOR ciphercube x intercube --> plaincube

        plain_cube = self.inverse_cube_XOR(cipher_cube, inter_cube)

        plaintext = plain_cube.flat_str().replace("$", "")  # flatten plaincube and remove filler

        try: #decodes the perm
            if self.mode == "bytes":
                plaintext = perm_to_byte(plaintext)
            if self.mode == "int":
                plaintext = perm_to_int(plaintext)
            if self.mode not in ("bytes", "int"):
                plaintext = perm_to_str_with_len(plaintext, self.mode)
        except:
            raise ValueError("plaintext: {plaintext} is in the wrong format or mismatched modes")

        return plaintext


# FOR CTR MODE

    def generate_auth_tag(self, ciphertext:list[str]): #generates auth_tag. Exclusive only to CTR mode
        ciphertext = b"" 
        for block in ciphertext:
            ciphertext ^= block
        return self.PRF(self.key_cube.get(), ciphertext, "auth_tag")


# TODO: rewrite for parallel processing
    def encrypt_ctr(self, plaintext:str|int|bytes):
        ciphertext_blocks = []
        old_mode = self.mode

# serialize plaintext to bytes
        plaintext = serialize(plaintext, self.mode)
        
        self.mode = "bytes" # set it to bytes for  CTR compatability


#split plaintext into size 25 bytes
        plain_blocks = []
        for i in range(0,len(plaintext), self.BLOCK_SIZE):
            block = plaintext[i:i + self.BLOCK_SIZE]
            if len(block) < self.BLOCK_SIZE:
                #  add PKCS#7 padding style here
                pad_len = self.BLOCK_SIZE - len(block)
                block += bytes([pad_len] * pad_len) # e.g, blocks size:8  A A A A A 3 3 3
                #                                                           padding ^^^^^
            plain_blocks.append(block)

        IV = os.urandom(16)

#cipher each block
        for i, block in enumerate(plain_blocks):
# encrypt each bluck with counter
            ciphertext, _ = self.encrypt(block,IV, i)
            ciphertext_blocks.append(ciphertext)


        self.mode = old_mode # restores old mode
        return ciphertext_blocks, IV # authentication done separately

    def decrypt_ctr(self, ciphertext_blocks, IV):
        #assumes authentication has been done
        plaintext_blocks = []
        
# decrypt each block        
        old_mode = self.mode
        self.mode = "bytes" # done for compatability
        for i, ciphertext in enumerate(ciphertext_blocks): # gets plaintext blocks
            plaintext = self.decrypt(ciphertext, IV, i)
            plaintext_blocks.append(plaintext)
        self.mode = old_mode # restores old mode


# join all blocks
        byte_data = b"".join(plaintext_blocks) # raw byte data with padding still
        pad_len = byte_data[-1]
        byte_data = byte_data[:-pad_len]



# deserialize + remove padding + remove terminating bytes
        
        plaintext = deserialize(byte_data, self.mode)

        return plaintext

# PUT WORKER FUNCTIONS HERE
# vvvvvvvvvvvvvvvvvvvvvvvvv

def main():
    #sample test input
    key_cube = mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW")

    cryptic_cube = CryptoCube(key_cube,mode="bytes")

    # A_moves, ciphertext = cryptic_cube.encrypt("hello")   # <= 25 bytes payload

    # print(A_moves,ciphertext)   # <= 25 bytes payload

    message_byte_size = 4_000

    message = b""
    for i in range(message_byte_size//4):
        message += b"a"

    ciphertext, IV = cryptic_cube.encrypt_ctr(message)
    tag = cryptic_cube.generate_auth_tag(ciphertext)


    print('======================================================================')
    print("ciphertext", ciphertext, IV)   

    plaintext = cryptic_cube.decrypt_ctr(ciphertext, IV)

    print(plaintext)



if __name__ == "__main__":
    main()

