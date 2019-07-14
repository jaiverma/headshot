import json
import numpy as np
import matplotlib.pyplot as plt

def parse_json(fname):
    data = ''
    with open(fname, 'r') as f:
        data = json.load(f)
    return data

def get_x_y(data):
    x = range(len(data['pitch']))
    y_a = data['pitch']
    y_b = data['yaw']
    return x, y_a, y_b

def diff_data(data):
    pitch = data['pitch']
    yaw = data['yaw']
    new_pitch_abs = []
    new_yaw_abs = []
    new_pitch = []
    new_yaw = []

    for i in range(len(pitch) - 1):
        new_pitch_abs.append(abs(pitch[i+1] - pitch[i]))
        new_yaw_abs.append(abs(yaw[i+1] - yaw[i]))
        new_pitch.append(pitch[i+1] - pitch[i])
        new_yaw.append(yaw[i+1] - yaw[i])

    data_abs = {}
    data_abs['pitch'] = new_pitch_abs
    data_abs['yaw'] = new_yaw_abs
    data = {}
    data['pitch'] = new_pitch
    data['yaw'] = new_yaw

    return data_abs, data


def get_features(data):
    stddev_pitch = np.std(data['pitch'])
    stddev_yaw = np.std(data['yaw'])
    mean_pitch = np.mean(data['pitch'])
    mean_yaw = np.mean(data['pitch'])

    _, diff = diff_data[data]

    stddev_pitch_diff = np.std(diff['pitch'])
    stddev_yaw_diff = np.std(diff['yaw'])
    mean_pitch_diff = np.mean(diff['pitch'])
    mean_yaw_diff = np.mean(diff['yaw'])

    return (
        stddev_pitch, mean_pitch, stddev_pitch_diff, mean_pitch_diff
    ), (
        stddev_yaw, mean_yaw, stddev_yaw_diff, mean_pitch_diff
    )

def plot_2d(**kwargs):
    x = kwargs['x']
    y1_a = kwargs['y1_a']
    y1_b = kwargs['y1_b']
    y2_a = kwargs['y2_a']
    y2_b = kwargs['y2_b']
    ylabel_a = kwargs['ylabel_a']
    ylabel_b = kwargs['ylabel_b']
    xlabel = kwargs['xlabel']
    title = kwargs['title']

    plt.subplot(2, 1, 1)
    plt.plot(x, y1_a, '--', color='r', label='Cheat')
    plt.plot(x, y2_a, '-', color='g', label='No cheat')
    plt.title(title)
    plt.ylabel(ylabel_a)

    plt.subplot(2, 1, 2)
    plt.plot(x, y1_b, '--', color='r', label='Cheat')
    plt.plot(x, y2_b, '-', color='g', label='No cheat')
    plt.ylabel(ylabel_b)
    plt.xlabel(xlabel)
    plt.legend()

    plt.show()

    # plt.savefig('plots/' + kwargs['name'], format='svg')
    # plt.close()

def plot_3d(cheat_data, no_cheat_data, title):
    xa = [i[0] for i in cheat_data]
    ya = [i[1] for i in cheat_data]
    za = [i[2] for i in cheat_data]

    xb = [i[0] for i in no_cheat_data]
    yb = [i[1] for i in no_cheat_data]
    zb = [i[2] for i in no_cheat_data]

    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')

    ax.scatter(xa, ya, za, marker='o', color='r', label='Cheat')
    ax.scatter(xb, yb, zb, marker='^', color='g', label='No cheat')

    ax.set_xlabel('Standard Deviation')
    ax.set_ylabel('Mean')
    ax.set_zlabel('Standard Deviation Diff')

    plt.title(title)
    plt.legend()

def main():
    cheat_data = parse_json('aim_data_cheat.json')
    no_cheat_data = parse_json('aim_data_no_cheat.json')

    x, y1_a, y1_b = get_x_y(cheat_data)
    _, y2_a, y2_b = get_x_y(no_cheat_data)
    plot(**{
        'x': x, 'y1_a': y1_a, 'y1_b': y1_b, 'y2_a': y2_a, 'y2_b': y2_b,
        'ylabel_a': 'Pitch', 'ylabel_b': 'Yaw', 'xlabel': 'Time', 'title': 'Pitch-Yaw Comparison',
        'name': 'pitch_yaw.svg'
        })

    diff_abs_cheat, diff_cheat = diff_data(cheat_data)
    diff_abs_no_cheat, diff_no_cheat = diff_data(no_cheat_data)

    x, y1_a, y1_b = get_x_y(diff_abs_cheat)
    _, y2_a, y2_b = get_x_y(diff_abs_no_cheat)
    plot(**{
        'x': x, 'y1_a': y1_a, 'y1_b': y1_b, 'y2_a': y2_a, 'y2_b': y2_b,
        'ylabel_a': 'Pitch Diff Abs', 'ylabel_b': 'Yaw Diff Abs', 'xlabel': 'Time', 'title': 'Pitch-Yaw Diff Abs Comparison',
        'name': 'pitch_yaw_abs_diff.svg'
        })

    x, y1_a, y1_b = get_x_y(diff_cheat)
    _, y2_a, y2_b = get_x_y(diff_no_cheat)
    plot(**{
        'x': x, 'y1_a': y1_a, 'y1_b': y1_b, 'y2_a': y2_a, 'y2_b': y2_b,
        'ylabel_a': 'Pitch Diff', 'ylabel_b': 'Yaw Diff', 'xlabel': 'Time', 'title': 'Pitch-Yaw Diff Comparison',
        'name': 'pitch_yaw_diff.svg'
        })

main()
