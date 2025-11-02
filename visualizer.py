from crypto_engine import CryptoCube

from magiccube import Cube as mCube
from rubik.cube import Cube as rCube
from helper import str_to_perm_with_len, perm_to_str_with_len
from helper import int_to_perm, perm_to_int, byte_to_perm, perm_to_byte
from magiccube import BasicSolver

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np


from helper import SOLVED_CUBE_STR

def display_flat_cube(colors: str,
                        labels: str,
                        colors_face_order: str = "URFDLB",
                        labels_face_order: str = "URFDLB",
                        figsize=(7,7)):
    """
    Display a Rubik net where `colors` and `labels` may use different face-concatenation orders.

    - colors: 54-char string (e.g. 'YYYYYYYYYRRRRRR...') describing colors in some face order.
    - labels: 54-char string/list describing labels (one per sticker) in some (possibly different) face order.
    - colors_face_order: 6-char permutation of 'U D L R F B' that describes the order in `colors`.
    - labels_face_order: likewise for `labels`.
    """
    labels = reformat_cube(labels)
    # --- validation
    if len(colors) != 54:
        raise ValueError("colors must be 54 characters")
    if isinstance(labels, str) and len(labels) != 54:
        raise ValueError("labels must be 54 characters or a list of 54 items")
    if len(colors_face_order) != 6 or len(labels_face_order) != 6:
        raise ValueError("face order strings must be 6 characters long using U D L R F B")

    # Convert labels to list of strings
    if isinstance(labels, str):
        labels_list = list(labels)
    else:
        labels_list = [str(x) for x in labels]

    # --- Build index mapping for faces in each input ordering:
    # Each face has 9 indices: face_order[i] -> indices [9*i ... 9*i+8]
    def face_indices_from_order(face_order_str):
        face_to_indices = {}
        for i, face in enumerate(face_order_str):
            start = 9 * i
            face_to_indices[face] = list(range(start, start + 9))
        return face_to_indices

    color_face_idx = face_indices_from_order(colors_face_order)
    label_face_idx = face_indices_from_order(labels_face_order)

    # --- Define net layout: where each face sits (row_start, col_start) in 3x3 cells
    # Layout grid (3 rows × 4 cols of faces) but we'll draw a 9x12 cell canvas
    net_face_positions = {
        'U': (0, 1),  # top center
        'L': (1, 0),
        'F': (1, 1),
        'R': (1, 2),
        'B': (1, 3),
        'D': (2, 1),  # bottom center
    }

    # --- Color lookup for character -> matplotlib color
    color_map = {
        'W': 'white', 'Y': 'yellow', 'R': 'red', 'O': 'orange', 'G': 'green', 'B': 'blue'
    }

    # Prepare figure and axes
    fig, ax = plt.subplots(figsize=figsize)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 9)
    ax.set_aspect('equal')
    ax.axis('off')

    # We will draw each face: for each face cell compute the color char index and label index.
    # For net row 0..2 (face rows) and col 0..3 (face cols):
    for face, (fr, fc) in net_face_positions.items():
        # these are the 3x3 positions inside that face on the net
        # idx_in_face runs 0..8 in row-major order
        # map to canvas coordinates: row canvas = fr*3 + local_row ; col canvas = fc*3 + local_col
        color_indices = color_face_idx.get(face)
        label_indices = label_face_idx.get(face)
        if color_indices is None or label_indices is None:
            # If user didn't place that face in their face_order, this will error; guard with blank face
            color_indices = [None]*9
            label_indices = [None]*9

        for local in range(9):
            lr = local // 3
            lc = local % 3
            canvas_row = fr*3 + lr
            canvas_col = fc*3 + lc

            # choose color char (safely)
            cidx = color_indices[local]
            if cidx is None:
                cchr = ' '  # empty
            else:
                cchr = colors[cidx]

            lidx = label_indices[local]
            if lidx is None:
                lab = ""
            else:
                lab = labels_list[lidx]

            # determine facecolor for matplotlib
            facecolor = color_map.get(cchr, 'lightgray')

            # Note: matplotlib's origin is bottom-left, but we want top-left origin for net
            # We'll invert y by using (8 - canvas_row) when placing the patch.
            x = canvas_col
            y = 8 - canvas_row

            rect = patches.Rectangle((x, y), 1, 1, facecolor=facecolor, edgecolor='black', linewidth=1)
            ax.add_patch(rect)

            # compute dynamic fontsize based on figure/pixel size & cell size
            # estimate pixels per data unit (x-axis units correspond to 12 width)
            bbox = fig.get_window_extent().transformed(fig.dpi_scale_trans.inverted())
            # bbox is in inches, times dpi -> pixels
            px_w = fig.get_size_inches()[0] * fig.dpi
            # one data unit horizontally corresponds to px_w / 12 pixels
            pixels_per_unit = px_w / 12.0
            # one cell is 1 data unit, so approx pixels_per_unit is cell pixel size
            cell_pixels = pixels_per_unit
            # fontsize: choose fraction of cell_pixels (empirical)
            fontsize = max(6, min( int(cell_pixels * 0.35), 24))

            # choose text color for contrast (black for light colors, white for dark)
            dark_faces = {'B','G','R','O'}  # heuristic: these characters usually dark-ish
            if cchr in dark_faces:
                txt_color = 'black'
            else:
                txt_color = 'black'

            ax.text(x + 0.5, y + 0.5, str(lab), ha='center', va='center',
                    fontsize=fontsize, color=txt_color, fontweight='bold')

    plt.tight_layout()
    plt.show()

def reformat_cube(cube_str):
    """
    Reformat a cube string from the 'net' layout (read top→bottom, left→right)
    into a face-ordered flattened string with face order U, R, F, L, B, D.
    """
    # Validate expected length
    if len(cube_str) != 54:
        raise ValueError(f"Expected 54 characters, got {len(cube_str)}.")

    # Mapping from your linear read to cube faces (each 3×3)
    # According to your ASCII layout, these are the index groups for each face:

    U = [0, 1, 2, 3, 4, 5, 6, 7, 8]
    L = [9, 10, 11, 21, 22, 23, 33, 34, 35]
    F = [12, 13, 14, 24, 25, 26, 36, 37, 38]
    R = [15, 16, 17, 27, 28, 29, 39, 40, 41]
    B = [18, 19, 20, 30, 31, 32, 42, 43, 44]
    D = [45, 46, 47, 48, 49, 50, 51, 52, 53]

    # Build faces
    def face(indices):
        return ''.join(cube_str[i] for i in indices)

    # Output order: U, R, F, L, B, D
    return ''.join([face(U), face(R), face(F), face(L), face(B), face(D)])

class Visualizer:
    def __init__(self, cube:CryptoCube):
        self.cube = cube
        self.key_cube = cube.key_cube
        self.mode = cube.mode
    def visualize_encrypt(self, A_moves, plaintext, ciphertext):
        
        try:
            if self.mode == "bytes":

                permutation = byte_to_perm(plaintext)
            if self.mode == "int":
                permutation = int_to_perm(plaintext)
            if self.mode not in ("bytes", "int"):
                permutation = str_to_perm_with_len(plaintext, self.mode)
                
            for i in (4,22,25,28,31,49):
                #insert middles in indexes 4, 22, 25, 28, 31, 49
                permutation.insert(i, '_')
        except:
            raise ValueError("plaintext: {plaintext} is in the wrong format or mismatched modes")

        permutation = "".join(permutation) #is a cubestring
        key_cube =  mCube(3, str(self.key_cube.get())) #ready to get the cube string
        permutation_cube = rCube(permutation)

        #First Display permutation + keycube
        print(permutation_cube)
        print(key_cube)

        display_flat_cube(key_cube.get(), permutation_cube.flat_str())


        #------------------------------------------------------------------
        
        key_cube.rotate(A_moves) #ready to get the cube string
        A_moves = A_moves.replace("'", "i")
        permutation_cube.sequence(A_moves) #ready to get the cube string

        #Second Display IV Cube + permutation after A_moves
        print(permutation_cube)
        print(key_cube)

        display_flat_cube(key_cube.get(), permutation_cube.flat_str())


        #------------------------------------------------------------------

        IV_cube = mCube(3, str(key_cube.get())) # From key to IV
        solver = BasicSolver(IV_cube) # Giseparate harun di mapil sa .history
        solver.solve()
        solver_moves = " ".join([str(i) for i in IV_cube.history()])
        solver_moves = solver_moves.replace("'", "i")
        permutation_cube.sequence(solver_moves) #ready to get the cube string

        #Third Display Ciphercube + findal ciphertext
        print(permutation_cube)
        print(IV_cube)

        display_flat_cube(IV_cube.get(), permutation_cube.flat_str())


        #------------------------------------------------------------------



        # print(permutation) # so now we have the permutation with $ in the middles

        # demo = rCube(SOLVED_CUBE_STR)

        # random_cube = mCube(3, str(self.key_cube.get()))

        # random_cube.scramble()
        # perm_cube = rCube(permutation)



        # # Visualization code for encryption process
        # perm_cube.sequence(A_moves)




        # Key Cube  summoning


        # Key Cube with symbols


        # Key Cube after A_moves


        # IV Cube to Ciphercube
         
        
        
        return
    
if __name__ == "__main__":
    #sample test input
    key_cube = mCube(3, "BYGWYYBBRYGWRRGORGRRWYGOYWBGRYGOWOYORBROBWBOGOBYGWOWBW")

    cryptic_cube = CryptoCube(key_cube)

    plaintext = "hello"
    A_moves, ciphertext = cryptic_cube.encrypt(plaintext)
    visualizer = Visualizer(cryptic_cube)
    print("""




VISUALIZATION OF ENCRYPTION PROCESS






""")
    visualizer.visualize_encrypt(A_moves, plaintext, ciphertext)
