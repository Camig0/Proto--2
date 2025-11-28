from rubik.cube import Cube as rCube
from magiccube import Cube as mCube
from magiccube import BasicSolver


def make_cube(moves:str, cube_type:bool=False):
    """cube type: true if rCube
                  false if mCube"""
    cube = mCube(3,"YYYYYYYYYRRRRRRRRRGGGGGGGGGOOOOOOOOOBBBBBBBBBWWWWWWWWW")
    cube.rotate(moves)
    if cube_type:
        cube = rCube("YYYYYYYYYRRRBBBOOOGGGRRRBBBOOOGGGRRRBBBOOOGGGWWWWWWWWW")
        cube.sequence(moves)
    return cube


key1 = make_cube("L R")
key2 = make_cube("U D")
key3  = make_cube("D F")

solver = BasicSolver(key1)
print(key1)
solver.solve()
print(key1)
print(key1.history())

flattened = [key.get() for key  in [key1, key2, key3]]

# print(flattened)
