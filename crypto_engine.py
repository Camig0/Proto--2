from blake3 import blake3

import os

import magiccube
from magiccube import Cube as mCube
from rubik.cube import Cube as rCube

from helper import str_to_perm_with_len, perm_to_str_with_len, int_to_perm, perm_to_int, byte_to_perm, perm_to_byte
from helper import seeded_random_cube, get_solve_moves, serialize, deserialize

from magiccube import BasicSolver

from helper import SOLVED_CUBE_STR

from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp
from functools import partial

#TODO: UPDATE workes so that they accept multiple keys
def encrypt_block(
            keys:list[str],
            block_data: bytes,
            IV:bytes|None=None,
            block:int=0,
            mode:str="bytes"
            ) -> str:
    from magiccube import Cube as mCube
    from rubik.cube import Cube as rCube # idk why imports are needed

    key_cubes = [mCube(3,key) for key in keys]

    cipher = CryptoCube(key_cubes, mode="bytes")
    
    ciphertext, _ = cipher.encrypt(block_data, IV, block)

    return (block, ciphertext)

    
def decrypt_block( keys:list[str], blockdata: str, IV:bytes,
            block:int=0, mode:str="bytes"
            ) -> str|int|bytes:
    from magiccube import Cube as mCube
    from rubik.cube import Cube as rCube # idk why imports are needed

    key_cubes = [mCube(3,key) for key in keys]

    cipher = CryptoCube(key_cubes, mode="bytes")
    
    plaintext = cipher.decrypt(blockdata, IV, block)

    return (block, plaintext)

def encrypt_wrapper(args:tuple):
    return encrypt_block(*args)

def decrypt_wrapper(args:tuple):
    return decrypt_block(*args)
    

class CryptoCube:
    def __init__(self, key_cubes:list[ mCube], mode="utf-8"):
        #mode tells the cipher what the expected plaintext and ciphertext is
        self.mode = mode
        self.BLOCK_SIZE = 25
        self.key_cube = key_cubes
        self.key_cubes = None
        if isinstance(key_cubes, list):
            self.key_cube = key_cubes[0]
            self.key_cubes = key_cubes

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

    # --- key whitten

    def whitten_plaintext(self, plaincube:rCube,keys:list[mCube]):
        for key in keys:
            clone_key = mCube(3, key.get())
            plaincube = self.cube_XOR(plaincube, clone_key)
        return plaincube

    def unwhitten_plaintext(self, plaincube, keys:list[mCube]):
        for key in reversed(keys):
            clone_key = mCube(3,key.get())
            plaincube = self.inverse_cube_XOR(plaincube, clone_key)
        return plaincube

    #TODO: CHANGE that instead of passing the keys itself as whittening material use seeded keys derived from IV
    def encrypt(self,
                plaintext: str|int|bytes,
                IV:bytes|None=None,
                block:int=0
                ) -> str:
        """
        Input: plaintext string
        Output: ciphertext encoded as a permutatuion of 54 symbols
        """
        try: # FOR bytes int and character codec compatability
            if self.mode == "bytes":
                permutation = byte_to_perm(plaintext)
            if self.mode == "int":
                permutation = int_to_perm(plaintext)
            if self.mode not in ("bytes", "int"):
                permutation = str_to_perm_with_len(plaintext, self.mode)
                
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
        ...
        # Plaintext whittening
        if self.key_cubes: #checks if key_cubes isnt None
            plain_cube = self.whitten_plaintext(plain_cube, self.key_cubes)

        # apply cube XOR on plaincube x intercube --> ciphercube

        cipher_cube = self.cube_XOR(plain_cube, inter_cube)

        ciphertext = cipher_cube.flat_str().replace("$", "") # flatten cipher cube and remove filler symbols ($)
        

        return ciphertext, IV # ciphertext + flattened IV

    def decrypt(self, ciphertext: str, IV:bytes,
                block:int=0
                ) -> str|int|bytes:
        key_cube = mCube(3, str(self.key_cube.get()))
        permutation = list(ciphertext)
        

        permutation = "".join(permutation)
        cipher_cube = rCube(permutation) # ciphercube

         # Reconstruct inter_cube using PRF using BLAKE3

        seed = self.PRF(key_cube.get(), IV + block.to_bytes(4, "big"), "keystream")
        # print("decryption seed",seed)

        inter_cube = seeded_random_cube(seed)

        # print(inter_cube)

        # Apply cube reverse XOR ciphercube x intercube --> plaincube

        plain_cube = self.inverse_cube_XOR(cipher_cube, inter_cube)

        #unwhitten
        if self.key_cubes: # if None then it means we dont keywhitten
            plain_cube = self.unwhitten_plaintext(plain_cube, self.key_cubes)

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
        ciphertext_data = b"\x00" * len(ciphertext[0].encode("utf-8")) # transforms permutation to bytes
        for block in ciphertext:
            block_bytes = block.encode('utf-8')
            # XOR byte by byte
            ciphertext_data = bytes(a ^ b for a, b in zip(ciphertext_data, block_bytes))
        return self.PRF(self.key_cube.get(), ciphertext_data, "auth_tag")



#TODO: change key args for workers so it accepts N keys
    def encrypt_ctr(self, plaintext:str|int|bytes, max_workers:int|None = None):
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

#Determine number of workers
        if max_workers is None:
            max_workers = min(mp.cpu_count(), len(plain_blocks))

        flat_keys = [str(self.key_cube.get())]
        if self.key_cubes:
            flat_keys = [str(key.get()) for key in self.key_cubes]

# Prepares args for each worker
        block_args = [
            (flat_keys,data, IV, idx, "bytes") for idx, data in enumerate(plain_blocks)
        ]

# pre-allocate space for ciphertext blocks
        ciphertext_blocks = [None for _ in plain_blocks]

# Parallel processing magic
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(
                encrypt_wrapper,
                block_args,
                chunksize=max(1, len(plain_blocks) // (max_workers * 4))
            )

# collect results
            for block,ciphertext in  results:
                ciphertext_blocks[block] = ciphertext

        self.mode = old_mode # restores old mode

# ---- Non- parallel processing code ----        

# #cipher each block
#         for i, block in enumerate(plain_blocks):
# # encrypt each bluck with counter
#             ciphertext, _ = self.encrypt(block,IV, i)
#             ciphertext_blocks.append(ciphertext)


#         self.mode = old_mode # restores old mode
        return ciphertext_blocks, IV # authentication done separately

#TODO: change key args for workers so it accepts N keys
    def decrypt_ctr(self, ciphertext_blocks, IV, max_workers:int=None):
        #assumes authentication has been done
        
# decrypt each block        
        old_mode = self.mode
        self.mode = "bytes" # done for compatability

# Determine number of workers

        if max_workers is None:
            max_workers = min(len(ciphertext_blocks), mp.cpu_count())

# Get all args for the wrapper
        flat_keys = [str(self.key_cube.get())]
        if self.key_cubes:
            flat_keys = [str(key.get()) for key in self.key_cubes]

        block_args = [
            (flat_keys, block, IV, idx, "bytes")
            for idx, block in  enumerate(ciphertext_blocks) 
        ]
# Pre-allocate space for plaintext blocks
        plaintext_blocks = [None for _ in  ciphertext_blocks]

# Parallel processing magic
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(
                decrypt_wrapper,
                block_args,
                chunksize=max(1, len(ciphertext_blocks) // (max_workers * 4))
            )
         
# Collect Results
            for block, plaintext in results:
                plaintext_blocks[block] = plaintext



        # for i, ciphertext in enumerate(ciphertext_blocks): # gets plaintext blocks
        #     plaintext = self.decrypt(ciphertext, IV, i)
        #     plaintext_blocks.append(plaintext)
        self.mode = old_mode # restores old mode


# join all blocks
        byte_data = b"".join(plaintext_blocks) # raw byte data with padding still
        pad_len = byte_data[-1]
        byte_data = byte_data[:-pad_len]



# deserialize + remove padding + remove terminating bytes
        
        plaintext = deserialize(byte_data, self.mode)

        return plaintext

    def test_whitten_unwhitten(self, message):
        print(f"original: {message}")
        permutation = byte_to_perm(message)
        permutation = "".join(permutation)
        plain_cube = rCube(permutation)
        print(plain_cube)
        plain_cube = self.whitten_plaintext(plain_cube, self.key_cubes)
        print(plain_cube)
        plain_cube = self.unwhitten_plaintext(plain_cube, self.key_cubes)
        print(plain_cube)
        return
# PUT WORKER FUNCTIONS HERE
# vvvvvvvvvvvvvvvvvvvvvvvvv

def main():
    # temp
    import time

    def timeit(func, *args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        print(f"{func.__name__} took {end - start:.6f} seconds")
        return result





    #sample test input
    key_cube = mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW")
    key2 = mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY")
    key3 = mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")

    cryptic_cube = CryptoCube([key_cube, key2, key3],mode="bytes")
    # cryptic_cube = CryptoCube(key_cube,mode="utf-8")

    # A_moves, ciphertext = cryptic_cube.encrypt("hello")   # <= 25 bytes payload

    # print(A_moves,ciphertext)   # <= 25 bytes payload


    message_byte_size = 400_000

    message = b"a" * message_byte_size

    # message = "i really wanna see if this can go way beyong the theoretical max bit cpapacity which is now longer now at 30 bytes which shoudl reduce number of blocks by 16% why the hell does it work first time i thought it was gonna take some more time why the helly  bird does it work" 
    
    ciphertext, IV = timeit(cryptic_cube.encrypt_ctr, message) 
    tag = timeit(cryptic_cube.generate_auth_tag, ciphertext)


    print('======================================================================')
    # print("ciphertext", ciphertext, IV)   

    plaintext = timeit(cryptic_cube.decrypt_ctr, ciphertext, IV)

    # print(f"Plaintext result: {plaintext}")



if __name__ == "__main__":
    main()

