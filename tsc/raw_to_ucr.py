import numpy as np
import sys

def tensor_to_ucr(file_path, cheat=False):
    tensor = np.fromfile(file_path, dtype=np.float32)
    tensor = list(tensor)
    tensor_str = ','.join(map(str, tensor))
    if cheat:
        tensor_str = '2,' + tensor_str
    else:
        tensor_str = '1,' + tensor_str
    return tensor_str

def main():
    ucr_data = tensor_to_ucr(sys.argv[1], False)
    print(ucr_data)

main()
