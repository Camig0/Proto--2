import argparse
from logger import log_to_file, print_log, reset_log, load_json
from magiccube import Cube as mCube
from crypto_engine import CryptoCube  # Replace with actual file name where CryptoCube lives
from tests import ConfusionDiffusionTest, MoveDistributionTest, PositionalDivergence
from datetime import datetime
from pprint import pprint

#CONSTANTS
MESSAGE_LOG_FILE = "message_logs.json"
TESTS_LOG_FILE = "test_logs.json"

def get_key_cube(key_string=None):
    # Default cube state if user doesn't provide one
    key_string = key_string or "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW"
    return mCube(3, key_string)

def encrypt_command(args):
    cube = get_key_cube(args.key)
    cryptic = CryptoCube(cube)

    A_moves, ciphertext = cryptic.encrypt(args.message)
    data = {"A_moves" : A_moves,"encrypted_message" : ciphertext}
    log_to_file(MESSAGE_LOG_FILE, data)
    print_log(MESSAGE_LOG_FILE)

def decrypt_command(args):
    cube = get_key_cube(args.key)
    cryptic = CryptoCube(cube)
    file = load_json(MESSAGE_LOG_FILE)


    message = file[args.message_index]
    A_moves = message["A_moves"]
    ciphertext = message["encrypted_message"]

    plaintext = cryptic.decrypt(A_moves, ciphertext)
    print(f"Notice: Decryption complete!")
    print(f"Plaintext: {plaintext}")

def test_command(args):
    test = args.test
    runs = args.runs
    trials = args.trials

    if test == "confusion_diffusion":
        tester = ConfusionDiffusionTest(runs=runs, trials=trials)
    if test == "move_distribution":
        tester = MoveDistributionTest(runs=runs, trials=trials)
    if test == "positional_kl_divergence":
        tester = PositionalDivergence(runs=runs, trials=trials)
    results = tester.do_test()
    pprint(results)
    time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    data = {time : results,
            "runs" : runs}
    log_to_file(TESTS_LOG_FILE, data)


def help_command(args):
    print("""
CryptoCube CLI - Help

Usage:
  python main.py <command> [options]

Commands:
  encrypt <message> [--key <key_string>]
      Encrypt a message. Use --key to specify a custom cube state.
      Example: python main.py encrypt "HELLO" --key "<cube_state>"

  decrypt <message_index> [--key <key_string>]
      Decrypt a message from the log by index (starting at 0).
      Example: python main.py decrypt 0

  log
      Show all saved encrypted messages.

  reset_log
      Clear the message log.

  help
      Show this help message.

Notes:
  - Log is saved in "message_logs.json".
  - Use the same key for encryption and decryption.
  - Due to Limitations, the max plaintext length is 25
""")
    
def reset_command(args):
    reset_log(MESSAGE_LOG_FILE)
    print_log(MESSAGE_LOG_FILE)

def log_command(args):
    print_log(MESSAGE_LOG_FILE)

def main():
    parser = argparse.ArgumentParser(description="CryptoCube CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Encrypt
    enc = subparsers.add_parser("encrypt", help="Encrypt a plaintext message")
    enc.add_argument("message", help="Plaintext to encrypt")
    enc.add_argument("--key", help="Optional custom key cube state")
    enc.set_defaults(func=encrypt_command)

    # Decrypt
    dec = subparsers.add_parser("decrypt", help="Decrypt a ciphertext")
    dec.add_argument("message_index", help="Index of message in the log")
    dec.add_argument("--key", help="Optional custom key cube state")
    dec.set_defaults(func=decrypt_command)

    # Help
    help = subparsers.add_parser("help", help="Help information")
    help.set_defaults(func=help_command)

    # Reset
    reset = subparsers.add_parser("reset_log", help="Reset log")
    reset.set_defaults(func=reset_command)

    # See Log
    log = subparsers.add_parser("log", help="See log")
    log.set_defaults(func=log_command)

    # Run Tests
    test = subparsers.add_parser("test", help="Test Confusion/Diffusion, Move Distribution KL Divergence, Ciphertext Positional KL Divergence")
    test.add_argument("test", help="What test to run", choices=["confusion_diffusion", "move_distribution", "positional_kl_divergence"])
    test.add_argument("--runs", help="Number of runs per trial", type=int, default=100)
    test.add_argument("--trials", help="Number of trials to run", type=int, default=3)
    test.set_defaults(func=test_command)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
