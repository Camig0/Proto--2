from crypto_engine import CryptoCube
from crypto_engine import *
from magiccube import Cube as mCube
import os

def round_trip_test(keys:list[mCube]):
    test_cases = [
        b"A", #single
        b"A" * 29, #one full block
        b"A" * 29 * 5, # multiple full blocks
        b"A" * 64, # multiple blocks, non-multiple of blocksize
        b"\x00" * 29, # block of all zeroes
        b"\xff" * 29, # full block 1
        os.urandom(100) #random data
    ]
    cipher = CryptoCube(keys, mode="bytes", whitten=False)

    for plaintext in test_cases:
        ciphertext, IV = cipher.encrypt_ctr(plaintext)
        recovered = cipher.decrypt_ctr(ciphertext, IV)
        assert recovered == plaintext, f"FAILED ON {plaintext.hex()}"

    print("roundtrip test: SUCESS")
    return True

def determinism_test(keys):
    """Same key + IV + plaintext -> same ciphertext"""
    cipher1 = CryptoCube(keys, mode="bytes")
    cipher2 = CryptoCube(keys, mode="bytes")
    
    plaintext = b"test message"
    iv = os.urandom(16)
    
    ct1, _ = cipher1.encrypt_ctr(plaintext)
    ct2, _ = cipher2.encrypt_ctr(plaintext)
    
    # Should be different (random IV)
    assert ct1 != ct2
    
    # With same IV should be identical
    cipher3 = CryptoCube(keys, mode="bytes")
    # Hack: force same IV (normally you'd expose this in the API)
    ct3 = [cipher3.encrypt(plaintext, iv, i)[0] for i in range(len(ct1))]
    ct4 = [cipher3.encrypt(plaintext, iv, i)[0] for i in range(len(ct1))]
    
    assert ct3 == ct4, "Non-deterministic encryption!"
    print("determinism test: SUCESS")
    return True

def key_sensitivity(keys1, keys2):
    """Different keys → different ciphertexts"""
    plaintext = b"A" * 30
    
    cipher1 = CryptoCube(keys1, mode="bytes")
    cipher2 = CryptoCube(keys2, mode="bytes")
    
    ct1, iv = cipher1.encrypt_ctr(plaintext)
    ct2, _ = cipher2.encrypt_ctr(plaintext)
    
    assert ct1 != ct2, "Different keys produced same ciphertext!"
    print("key sensitivity: SUCESS")
    return True

def bug_tests():
    KEYS1 = [mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"), mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY"), mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")]
    KEYS2 = [mCube(3, "OOYYGYYGRWRRGRRYRRGWBGWYGWGWOOBOOYOOBGGBYYBBBWBOWBWRRW"), mCube(3, "YGGYGBWRROOORRRYYOGWYGWYBBBBORBORRWYWWGYYBBORWWWGBOGGO"), mCube(3,"WRBWYYGWWRRYGGOBBBROOYOROBOGRWBBBGGBRGGOROWGRYWYYWYYWO")]
    round_trip_test_rslt = round_trip_test(KEYS1)
    determinism_test_rslt = determinism_test(KEYS2)
    key_sensitivity_rslt = key_sensitivity(KEYS1, KEYS2)
    results = {"round trip":round_trip_test_rslt, "determinism test":determinism_test_rslt, "key sensitivity" : key_sensitivity_rslt}

    return results


def main():
    key1 = mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW")
    key2 = mCube(3, "YGBRGWWWYOBGWRYORBROBRWORBRRBOGOBYWBWYGYYROYGWOGGBGWOY")
    key3 = mCube(3,"GOBRGGBOORWOYRBWBOWWYOWYWBBGWYGOYYGROGYOYBWYGGRRWBRRRB")

    cipher = CryptoCube([key1,key2,key3], mode="bytes")

    message_size = 2000
    message = b"a" * message_size

    ciphertext, IV = cipher.encrypt_ctr(message)

    plaintext = cipher.decrypt_ctr(ciphertext, IV)

    print(plaintext)
    print(bug_tests())

if __name__ == "__main__":
    main()