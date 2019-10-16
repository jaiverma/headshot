from random import shuffle

def shuffle_file(fname):
    l = []
    with open(fname) as f:
        for line in f:
            l.append(line.strip())
    shuffle(l)
    with open(fname, 'w') as f:
        for line in l:
            f.write(line + '\n')

def main():
    shuffle_file('ac_pitch_TRAIN')
    shuffle_file('ac_yaw_TRAIN')

main()
