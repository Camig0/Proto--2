import customtkinter as ctk
from tkinter import messagebox

from magiccube import Cube as mCube
from rubik.cube import Cube as rCube
from crypto_engine import CryptoCube
from visualizer import Visualizer
from visualizer import GeneralVisualizer

import helper
import base64

# Appearance
ctk.set_appearance_mode("dark")  # "dark" mode
ctk.set_default_color_theme("dark-blue")


class RubikCipherGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Project C.I.P.H.E.R. (demo)")
        self.geometry("820x560")
        self.resizable(False, False)

        # Data storage
        self.stored_key_sequence = ""  # stored after encryption step (for internal check only)
        self.ciphertext = ""           # stored ciphertext
        self.move_list = []            # temporary during key entry

        # Create main container
        self.container = ctk.CTkFrame(self, corner_radius=8)
        self.container.pack(fill="both", expand=True, padx=20, pady=20)

        # Create screens
        self.create_encrypt_input_screen()
        self.create_key_entry_screen_encrypt()
        self.create_cipher_display_screen()
        self.create_key_entry_screen_decrypt()
        self.create_plain_display_screen()

        # Start with encrypt input screen
        self.show_frame(self.encrypt_input_frame)

    # -----------------------
    # Screen creation methods
    # -----------------------
    def create_encrypt_input_screen(self):
        frame = ctk.CTkFrame(self.container)
        self.encrypt_input_frame = frame

        title = ctk.CTkLabel(frame, text="Encrypt Message", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(20, 10))

        msg_label = ctk.CTkLabel(frame, text="Enter plaintext to encrypt:", anchor="w")
        msg_label.pack(fill="x", padx=24, pady=(8, 6))

        self.plaintext_box = ctk.CTkTextbox(frame, width=740, height=180)
        self.plaintext_box.pack(padx=24)

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=18)

        next_btn = ctk.CTkButton(btn_frame, text="Next →", command=self.on_next_from_plaintext, width=140)
        next_btn.pack()

    def create_key_entry_screen_encrypt(self):
        frame = ctk.CTkFrame(self.container)
        self.key_entry_encrypt_frame = frame

        title = ctk.CTkLabel(frame, text="Key Entry (Encryption) Genereate a key", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(14, 6))

        prompt = ctk.CTkLabel(frame, text="What key do we use to encrypt?", anchor="w")
        prompt.pack(fill="x", padx=24, pady=(6, 8))

        # Move buttons grid
        moves_frame = ctk.CTkFrame(frame)
        moves_frame.pack(padx=24, pady=(0, 10))

        moves = ["U", "U'", "R", "R'", "L", "L'", "D", "D'", "F", "F'", "B", "B'"]
        row = 0
        col = 0
        for i, m in enumerate(moves):
            btn = ctk.CTkButton(moves_frame, text=m, width=80, height=40,
                                command=lambda move=m: self.add_move(move))
            btn.grid(row=row, column=col, padx=6, pady=6)
            col += 1
            if col % 4 == 0:
                row += 1
                col = 0

        # Sequence display and control buttons
        seq_frame = ctk.CTkFrame(frame, fg_color="transparent")
        seq_frame.pack(fill="x", padx=24, pady=(6, 8))

        seq_label = ctk.CTkLabel(seq_frame, text="Entered key sequence:")
        seq_label.pack(anchor="w")

        self.key_sequence_display = ctk.CTkTextbox(seq_frame, height=80, width=740)
        self.key_sequence_display.pack(pady=(6, 8))

        control_frame = ctk.CTkFrame(seq_frame, fg_color="transparent")
        control_frame.pack(anchor="e", pady=(0, 6))

        back_btn = ctk.CTkButton(control_frame, text="Backspace", width=110, command=self.backspace_move)
        back_btn.grid(row=0, column=0, padx=6)

        clear_btn = ctk.CTkButton(control_frame, text="Clear", width=80, command=self.clear_moves)
        clear_btn.grid(row=0, column=1, padx=6)

        encrypt_btn = ctk.CTkButton(frame, text="Encrypt", width=160, command=self.on_encrypt_clicked)
        encrypt_btn.pack(pady=(6, 16))

    def create_cipher_display_screen(self):
        frame = ctk.CTkFrame(self.container)
        self.cipher_display_frame = frame

        title = ctk.CTkLabel(frame, text="Ciphertext", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(18, 10))

        ct_label = ctk.CTkLabel(frame, text="Ciphertext output:")
        ct_label.pack(fill="x", padx=24, pady=(6, 6))

        self.ciphertext_box = ctk.CTkTextbox(frame, width=740, height=180)
        self.ciphertext_box.pack(padx=24)

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=(14, 8))

        decrypt_btn = ctk.CTkButton(btn_frame, text="Decrypt →", width=140, command=self.on_decrypt_from_cipher)
        decrypt_btn.pack()

    def create_key_entry_screen_decrypt(self):
        frame = ctk.CTkFrame(self.container)
        self.key_entry_decrypt_frame = frame

        title = ctk.CTkLabel(frame, text="Key Entry (Decryption)", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(14, 6))

        prompt = ctk.CTkLabel(frame, text="What key was used to encrypt?", anchor="w")
        prompt.pack(fill="x", padx=24, pady=(6, 8))

        # Move buttons (same layout)
        moves_frame = ctk.CTkFrame(frame)
        moves_frame.pack(padx=24, pady=(0, 10))

        moves = ["U", "U'", "R", "R'", "L", "L'", "D", "D'", "F", "F'", "B", "B'"]
        row = 0
        col = 0
        for i, m in enumerate(moves):
            btn = ctk.CTkButton(moves_frame, text=m, width=80, height=40,
                                command=lambda move=m: self.add_move(move))
            btn.grid(row=row, column=col, padx=6, pady=6)
            col += 1
            if col % 4 == 0:
                row += 1
                col = 0

        seq_frame = ctk.CTkFrame(frame, fg_color="transparent")
        seq_frame.pack(fill="x", padx=24, pady=(6, 8))

        seq_label = ctk.CTkLabel(seq_frame, text="Re-enter the key sequence:")
        seq_label.pack(anchor="w")

        self.key_sequence_display_decrypt = ctk.CTkTextbox(seq_frame, height=80, width=740)
        self.key_sequence_display_decrypt.pack(pady=(6, 8))

        control_frame = ctk.CTkFrame(seq_frame, fg_color="transparent")
        control_frame.pack(anchor="e", pady=(0, 6))

        back_btn = ctk.CTkButton(control_frame, text="Backspace", width=110, command=self.backspace_move)
        back_btn.grid(row=0, column=0, padx=6)

        clear_btn = ctk.CTkButton(control_frame, text="Clear", width=80, command=self.clear_moves)
        clear_btn.grid(row=0, column=1, padx=6)

        decrypt_btn = ctk.CTkButton(frame, text="Decrypt", width=160, command=self.on_decrypt_clicked)
        decrypt_btn.pack(pady=(6, 16))

    def create_plain_display_screen(self):
        frame = ctk.CTkFrame(self.container)
        self.plain_display_frame = frame

        title = ctk.CTkLabel(frame, text="Decrypted Plaintext", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(18, 10))

        pt_label = ctk.CTkLabel(frame, text="Recovered message:")
        pt_label.pack(fill="x", padx=24, pady=(6, 6))

        self.plaintext_box_out = ctk.CTkTextbox(frame, width=740, height=180)
        self.plaintext_box_out.pack(padx=24)

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=(14, 8))

        restart_btn = ctk.CTkButton(btn_frame, text="Restart", width=140, command=self.restart_flow)
        restart_btn.pack()

    # -----------------------
    # Navigation utilities
    # -----------------------
    def show_frame(self, frame):
        # Remove any existing children in container and pack the chosen frame
        for widget in self.container.winfo_children():
            widget.pack_forget()
        frame.pack(fill="both", expand=True)

        # reset move list when a fresh key entry screen is shown
        if frame in (self.key_entry_encrypt_frame, self.key_entry_decrypt_frame):
            self.clear_moves()

    # -----------------------
    # Move sequence handlers
    # -----------------------
    def add_move(self, move):
        self.move_list.append(move)
        self.update_move_displays()

    def backspace_move(self):
        if self.move_list:
            self.move_list.pop()
            self.update_move_displays()

    def clear_moves(self):
        self.move_list = []
        self.update_move_displays()

    def update_move_displays(self):
        seq_text = " ".join(self.move_list)
        # update the correct textbox depending on which key screen is visible (encrypt/decrypt)
        # write to both; caller logic will use correct one
        try:
            self.key_sequence_display.delete("0.0", "end")
            self.key_sequence_display.insert("0.0", seq_text)
        except Exception:
            pass

        try:
            self.key_sequence_display_decrypt.delete("0.0", "end")
            self.key_sequence_display_decrypt.insert("0.0", seq_text)
        except Exception:
            pass

    # -----------------------
    # Button callbacks / flow
    # -----------------------
    def on_next_from_plaintext(self):
        # Move to key entry screen for encryption
        plaintext = self.plaintext_box.get("0.0", "end").strip()
        if not plaintext:
            messagebox.showwarning("Input required", "Please enter a plaintext message to encrypt.")
            return
        if len(plaintext) > 25:
            messagebox.showwarning("Too long", "Plaintext must be 25 characters or fewer.")
            return
        
        self.show_frame(self.key_entry_encrypt_frame)

    def on_encrypt_clicked(self):
        plaintext = self.plaintext_box.get("0.0", "end").strip()
        key_seq = " ".join(self.move_list).strip()

        if not key_seq:
            messagebox.showwarning("Key required", "Please enter a key sequence using the move buttons.")
            return
        # matplotlib here
        demo_key_cube = mCube(3,helper.SOLVED_KEY_CUBE)
        demo_key_cube.rotate(key_seq)
        visualizer = GeneralVisualizer(demo_key_cube)
        visualizer.visualize()



        # store the key internally (temporary)
        self.stored_key_sequence = key_seq

        # TODO: Replace encrypt_placeholder with your Rubik-cube-based encryption function
        # It should accept plaintext and key sequence (string) and return a ciphertext string.
        self.ciphertext = self.encrypt_placeholder(plaintext, key_seq)

        # display ciphertext
        self.ciphertext_box.delete("0.0", "end")
        self.ciphertext_box.insert("0.0", self.ciphertext)

        # clear moves for next entry (user will have to re-enter for decryption)
        self.clear_moves()

        # move to ciphertext screen
        self.show_frame(self.cipher_display_frame)

    def on_decrypt_from_cipher(self):
        # Move to key entry screen for decryption
        if not self.ciphertext:
            messagebox.showwarning("No ciphertext", "There is no ciphertext to decrypt. Encrypt a message first.")
            return
        self.show_frame(self.key_entry_decrypt_frame)

    def on_decrypt_clicked(self):
        entered_key = " ".join(self.move_list).strip()
        if not entered_key:
            messagebox.showwarning("Key required", "Please re-enter the key sequence to decrypt.")
            return

        # Compare keys; if mismatch -> simulate cipher rejecting the key
        if entered_key != self.stored_key_sequence:
            messagebox.showerror("Wrong Key", "The entered key does not match the key used to encrypt. Decryption aborted.")
            return

        # TODO: Replace decrypt_placeholder with your Rubik-cube-based decryption function
        plaintext = self.decrypt_placeholder(self.ciphertext, entered_key)

        self.plaintext_box_out.delete("0.0", "end")
        self.plaintext_box_out.insert("0.0", plaintext)

        # move to plaintext display
        self.show_frame(self.plain_display_frame)

    def restart_flow(self):
        # Clear everything and go back to start
        self.plaintext_box.delete("0.0", "end")
        self.plaintext_box_out.delete("0.0", "end")
        self.ciphertext_box.delete("0.0", "end")
        self.stored_key_sequence = ""
        self.ciphertext = ""
        self.clear_moves()
        self.show_frame(self.encrypt_input_frame)

    # -----------------------
    # Placeholder encryption / decryption
    # -----------------------
    def encrypt_placeholder(self, plaintext: str, key_sequence: str) -> str:
        """
        Placeholder encryption: combines plaintext and key then base64-encodes.
        Replace this with your actual Rubik-cube-based encryption function.
        """
        # NOTE: This is *only* a mock. Replace with your real cipher.
        #Key sequence is sequence of moves with i as '
        key_cube = mCube(3,helper.SOLVED_KEY_CUBE)
        key_cube.rotate(key_sequence)
        cryptic_cube = CryptoCube(key_cube)

        self.A_moves, ciphertext = cryptic_cube.encrypt(plaintext)
        visualizer = Visualizer(cryptic_cube)
        visualizer.visualize_encrypt(self.A_moves, plaintext, ciphertext)

        return ciphertext

    def decrypt_placeholder(self, ciphertext: str, key_sequence: str) -> str:
        """
        Placeholder decryption matching encrypt_placeholder.
        In your real implementation, decrypt using your algorithm.
        """
        key_cube = mCube(3,helper.SOLVED_KEY_CUBE)
        key_cube.rotate(key_sequence)
        cryptic_cube = CryptoCube(key_cube)

        plaintext = cryptic_cube.decrypt(self.A_moves, ciphertext)

        visualizer = Visualizer(cryptic_cube)
        visualizer.visualize_decrypt(self.A_moves, plaintext, ciphertext)
        
        return plaintext

print('oh days')
if __name__ == "__main__":
    print("yo")
    app = RubikCipherGUI()
    app.mainloop()
    print("exit")
print("exit again")