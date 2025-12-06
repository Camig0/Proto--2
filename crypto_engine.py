"""CRYPTO ENGINE :)"""
from blake3 import blake3

import os

import magiccube
from magiccube import Cube as mCube
from rubik.cube import Cube as rCube

from helper import seeded_random_cube, get_solve_moves, serialize, deserialize, pad_with_random, unpad_random, blake3_combine

from magiccube import BasicSolver

from helper import SOLVED_CUBE_STR, BYTES_PAYLOAD, _ELEMENTS

from concurrent.futures import ProcessPoolExecutor
import multiprocessing as mp
from functools import partial

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
    def __init__(self, master_key_cubes:list[mCube], mode="utf-8", whitten:bool=True):
        #mode tells the cipher what the expected plaintext and ciphertext is
        self.mode = mode
        self.BLOCK_SIZE = 54

        self.master_keys:list[mCube] = master_key_cubes
        self.encryption_key:bytes = self._derive_key_material("encryption_key")
        self.auth_key:bytes = self._derive_key_material("auth_key")
        self.sbox_key:bytes = self._derive_key_material("sbox_key")
        self.XOR_key:bytes = self._derive_key_material("XOR key", 34)

        self.whittening_cubes = None
        if whitten:
            self.whittening_cubes:list[bytes] = [
                self._derive_key_material(f"whittening-{i}")
                for i in range(len(master_key_cubes))
            ]
    
# credit to claude for KDF
    def _derive_key_material(self, purpose: str, length: int = 32) -> bytes:
        """
        Derive cryptographic key material (bytes) for PRF/MAC operations.
        
        This is used for:
        - PRF inputs (keystream generation)
        - Authentication tag generation
        - Any operation that needs raw bytes
        """
        hasher = blake3()
        
        # Mix all master keys
        for key_cube in self.master_keys:
            hasher.update(key_cube.get().encode('utf-8'))
        
        # Add purpose separation
        hasher.update(purpose.encode('utf-8'))
        
        # Expand to desired length
        output = b""
        counter = 0
        
        while len(output) < length:
            h = blake3()
            h.update(hasher.digest())
            h.update(counter.to_bytes(4, 'big'))
            output += h.digest()
            counter += 1
        
        return output[:length]
    
    def _derive_cube_key(self, purpose: str) -> mCube:
        """
        Derive a scrambled cube key (mCube object) for cube operations.
        
        This is used for:
        - Whitening operations
        - Cube XOR operations
        - Any operation that needs an actual cube state
        """
        # Get seed from master keys
        seed = self._derive_key_material(purpose, length=32)
        
        # Generate a scrambled cube using the seed
        derived_cube = seeded_random_cube(seed, length=50)
        
        return derived_cube

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

    def PRF(self, key:bytes, context:bytes, purpose:str):
        hasher = blake3()
        hasher.update(key)
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

    # --- S- BOX

    def key_sbox(self,key: bytes, context:bytes = b"") -> list:
        """
        Generate a deterministic, cryptographically secure S-box using BLAKE3 in keyed mode.
        Returns a permutation of 0..255 (bijection).
        """
        # BLAKE3 keyed hash
        rng = blake3(key=key)
        rng.update(context)

        sbox = list(range(256))

        # Fisher–Yates shuffle, with BLAKE3 providing random bytes
        for i in range(255, -1, -1):
            rng.update(bytes([i]))  # domain separation
            rnd = int.from_bytes(rng.digest(4), 'little')
            j = rnd % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]

        return sbox


    def apply_sbox(self,data: bytes, sbox: list) -> bytes:
        """
        Apply the S-box to each byte.
        """
        return bytes(sbox[b] for b in data)


    def reverse_sbox(self,data: bytes, key: bytes, context:bytes = b"") -> bytes:
        """
        Reverse the S-box via key regeneration.
        """
        sbox = self.key_sbox(key,context)
        inv = [0] * 256
        for i, v in enumerate(sbox):
            inv[v] = i
        return bytes(inv[b] for b in data)
    

    # key stream XOR

    def xor_keystream(self,msg: bytes, keystream: bytes) -> bytes:
        if len(keystream) < len(msg):
            raise ValueError("keystream must be at least as long as the message")

        return bytes([m ^ k for m, k in zip(msg, keystream)])

    def xor_keystream_reverse(self, cipher: bytes, keystream: bytes) -> bytes:
        if len(keystream) < len(cipher):
            raise ValueError("keystream must be at least as long as the ciphertext")

        return bytes([c ^ k for c, k in zip(cipher, keystream)])


    def encrypt(self,
                plaintext: str|int|bytes,
                IV:bytes|None=None,
                block:int=0
                ) -> bytes:
        """
        Input: plaintext string
        Output: ciphertext encoded as a permutatuion of 54 symbols
        """
        if not IV: #if IV == None generate an IV, used when doing simple encrypt of just one block
            IV = os.urandom(16) # Nonce
        context = IV + block.to_bytes(4, "big")
        plainbytes = b""
        payload = b""
        try: # FOR bytes int and character codec compatability
            plainbytes = serialize(plaintext, self.mode)
            if len(plaintext) == BYTES_PAYLOAD:
                payload = plainbytes
            
            elif len(plaintext) < BYTES_PAYLOAD:
                #right pad
                pad_length = (self.BLOCK_SIZE - len(plainbytes)).to_bytes(1, "big")
                padded = pad_with_random(plainbytes, self.BLOCK_SIZE, context)
                payload = padded

            else:
                print(len(plaintext))
                raise
    
        except:
            raise ValueError("plaintext: {plaintext} is in the wrong format or mismatched modes")

        permutation = "".join(_ELEMENTS)

        

        #clone the key
        # initializes as keycube then scrambles 
        # scramble sequence is moves A
        plain_cube = rCube(permutation) #plain cube

        # PRF using BLAKE3 to get cube

        seed = self.PRF(self.encryption_key, IV + block.to_bytes(4, "big"), "keystream") #uses blake3

        inter_cube = seeded_random_cube(seed) #untested output
        # Plaintext whittening
        if self.whittening_cubes: #checks if key_cubes isnt None
            concatenated_key = b"".join(self.whittening_cubes)
            whittening_seed =  self.PRF(concatenated_key, IV + block.to_bytes(4, "big"), "whittening keystream")
            keystream_cubes = [seeded_random_cube(whittening_seed + bytes(i)) for i, _ in enumerate(self.whittening_cubes)]

            plain_cube = self.whitten_plaintext(plain_cube, keystream_cubes)

        # apply cube XOR on plaincube x intercube --> ciphercube

        cipher_cube = self.cube_XOR(plain_cube, inter_cube)

        shuffle = cipher_cube.flat_str().replace("$", "") # flatten cipher cube and remove filler symbols ($)
        
        shuffled_indices = [_ELEMENTS.index(i) for i in shuffle ]
        # APPLY S-BOX\
        sbox = self.key_sbox(self.sbox_key,context)
        payload = self.apply_sbox(payload,sbox) #sbox

        payload = self.xor_keystream(payload,blake3_combine(len(payload), self.XOR_key, context))

        ciphertext = b"".join(payload[i:i+1] for i in shuffled_indices) #shuffle

        
        return ciphertext, IV # ciphertext + flattened IV

    def decrypt(self, ciphertext: bytes, IV:bytes,
                block:int=0
                ) -> str|int|bytes:
        permutation = "".join(_ELEMENTS)

        context = IV + block.to_bytes(4, "big")
        
        cipher_cube = rCube(permutation) # ciphercube

         # Reconstruct inter_cube using PRF using BLAKE3

        seed = self.PRF(self.encryption_key, context, "keystream")
        # print("decryption seed",seed)

        inter_cube = seeded_random_cube(seed)

        # Apply cube reverse XOR ciphercube x intercube --> plaincube

        plain_cube = self.inverse_cube_XOR(cipher_cube, inter_cube)

        #unwhitten
        if self.whittening_cubes: # if None then it means we dont keywhitten
            concatenated_key = b"".join(self.whittening_cubes)
            whittening_seed =  self.PRF(concatenated_key, context, "whittening keystream")
            keystream_cubes = [seeded_random_cube(whittening_seed + bytes(i)) for i, _ in enumerate(self.whittening_cubes)]

            plain_cube = self.unwhitten_plaintext(plain_cube, keystream_cubes)

        unshuffled = plain_cube.flat_str().replace("$", "")  # flatten plaincube and remove filler
        unshuffled_indices = [_ELEMENTS.index(i) for i in unshuffled ]

        plaintext = b"".join(ciphertext[i:i+1] for i in unshuffled_indices) # unshuffle
        plaintext = self.xor_keystream_reverse(plaintext, blake3_combine(len(ciphertext), self.XOR_key, context)) # XOR thingy mabooty
        plaintext = self.reverse_sbox(plaintext, self.sbox_key, context) #un s-box


        try: #decodes the perm
            unpadded = unpad_random(plaintext, context)

            return deserialize(unpadded,self.mode)
            
        except:
            return deserialize(plaintext,self.mode)


# FOR CTR MODE

    def generate_auth_tag(self, ciphertext:list[str]): #generates auth_tag. Exclusive only to CTR mode
        ciphertext_data = b"\x00" * len(ciphertext[0].encode("utf-8")) # transforms permutation to bytes
        for block in ciphertext:
            block_bytes = block.encode('utf-8')
            # XOR byte by byte
            ciphertext_data = bytes(a ^ b for a, b in zip(ciphertext_data, block_bytes))
        return self.PRF(self.auth_key, ciphertext_data, "auth_tag")



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
            plain_blocks.append(block)

        if len(plaintext) == 0:
            plain_blocks = [bytes([self.BLOCK_SIZE] * self.BLOCK_SIZE)]

        

        IV = os.urandom(16)

#Determine number of workers
        if max_workers is None:
            max_workers = min(mp.cpu_count(), len(plain_blocks))

        flat_keys = [str(key.get()) for key in self.master_keys]

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
        return b"".join(ciphertext_blocks), IV # authentication done separately


    def decrypt_ctr(self, ciphertext:bytes, IV, max_workers:int=None):
        #assumes authentication has been done
        ciphertext_blocks = []
        for i in range(0,len(ciphertext), self.BLOCK_SIZE):
            block = ciphertext[i:i + self.BLOCK_SIZE]
            ciphertext_blocks.append(block)


# decrypt each block        
        old_mode = self.mode
        self.mode = "bytes" # done for compatability

# Determine number of workers

        if max_workers is None:
            max_workers = min(len(ciphertext_blocks), mp.cpu_count())

# Get all args for the wrapper
        flat_keys = [str(key.get()) for key in self.master_keys]

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
        
        #padding validation
        if len(byte_data) > 0:
            pad_len = byte_data[-1]
        
        # Validate padding: pad_len should be between 1 and BLOCK_SIZE
        # and all padding bytes should have the same value
            if 1 <= pad_len <= self.BLOCK_SIZE:
                # Check if all padding bytes are correct
                padding = byte_data[-pad_len:]
                if all(b == pad_len for b in padding):
                    byte_data = byte_data[:-pad_len]
        # fixes issue where if message length was a modulo of the block size it reads the last meaningful bit as pad_len even tho it rlly isnt... kinda dum  so i just set it to zero
        # if len(byte_data) % (self.BLOCK_SIZE + 1) == 0: 
        #     return deserialize(byte_data, self.mode)



# deserialize + remove padding + remove terminating bytes
        
        plaintext = deserialize(byte_data, self.mode)

        return plaintext

# PUT WORKER FUNCTIONS HERE
# vvvvvvvvvvvvvvvvvvvvvvvvv

def main():
    # temp
    import time

    def timeit(func, *args, **kwargs):
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        # print(f"{func.__name__} took {end - start:.6f} seconds")
        return result





    #sample test input
    key_cube = mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW")
    key2 = mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY")
    key3 = mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")

    cryptic_cube = CryptoCube([key_cube, key2, key3],mode="bytes", whitten= False)
    # cryptic_cube = CryptoCube(key_cube,mode="utf-8")

    # A_moves, ciphertext = cryptic_cube.encrypt("hello")   # <= 25 bytes payload

    # print(A_moves,ciphertext)   # <= 25 bytes payload


    message_byte_size = 200

    message =  b'aby\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19\x19'
    message = b'qazwsxedcrfvtgbyhnujmiklopqa' # 28 len
    # message = b'qazwsxedcrfvtgbyhnujmodpqa' # 25 len
    # message = "IM JUST GONNA HIDE HERE AS SOME NON-CONSIPICUOUS "

    run = 0
    while True: 
        # message = b'\x958i\xf0_7\xd4\xcd\xd4\x13Pho H\x95\x14\x95\xf0\x9c\xeaU\x1ec\x12k\x9bX\x0cis\xcb\x0f\xf7N\xf2n)\xa4\xa9\xdd\x82\xbb\xd0UQ\xb6\xb5\xd1\xf4\xb4d#5'
        message = os.urandom(10 * 1024 * 1024)
        run +=1
        print(run)
        # message = "i really wanna see if this can go way beyong the theoretical max bit cpapacity which is now longer now at 30 bytes which shoudl reduce number of blocks by 16% why the hell does it work first time i thought it was gonna take some more time why the helly  bird does it work" 
        
        ciphertext, IV = timeit(cryptic_cube.encrypt_ctr, message) 
        # tag = timeit(cryptic_cube.generate_auth_tag, ciphertext)


        # print('======================================================================')
        # print("ciphertext", ciphertext, IV)   

        plaintext = timeit(cryptic_cube.decrypt_ctr, ciphertext, IV)
        # print(tag)
        # print("\n============================================\n")
        # print(message)
        # print("\n============================================\n")
        # print(plaintext)
        # print("\n============================================\n")
        # print(ciphertext)

        assert plaintext == message



if __name__ == "__main__":
    main()