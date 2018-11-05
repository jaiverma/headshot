from player import Player
from threading import Thread
from IPython import embed

import scan
import sys
import math
import numpy as np
import struct

if len(sys.argv) < 2:
    print('Usage: {} <pid>'.format(sys.argv[0]))
    sys.exit(1)

class Trainer:
    def __init__(self, pid):
        self._pid = pid
        self._player_ptr = 0x12b8a8
        self._enemy_vector_ptr = self._player_ptr + 0x4
        self._enemy_count_ptr = self._player_ptr + 0xc
        self._view_matrix_ptr = 0x133594
        # 0x133554, 0x133594, 0x1335d4, 0x133614
        self._window_width_ptr = 0x12e4ac
        self._window_height_ptr = 0x12e4b0
        self._m = scan.Mem(int(pid))
        self._player_count = self._m.read_mem('u32', self._enemy_count_ptr)
        self._offsets = {
            'health': [0xf8],
            'weapon_ammo': [0x374, 0x10, 0x0],
            'weapon_clip': [0x374, 0x14, 0x0],
            'player_name': [0x225],
            'head_vector3f': [0x4],
            'foot_vector3f': [0x34],
            'yaw': [0x40],
            'pitch': [0x44],
            'toggle_aimbot': [0x32c]
        }
        self.player = Player(self._player_ptr, self._m)

    def _read_view_matrix(self):
        # read 4*4 matrix
        addr = self._view_matrix_ptr
        data = ''
        for i in range(1, 17):
            data += str(self._m.read_mem('f', addr))
            data += ' '
            if i % 4 == 0:
                data += ';'
            addr += self._m.ptr_size
        data = data.strip(';')
        return np.matrix(data)

    def _get_enemies(self):
        enemies = []
        for i in range(1, self._player_count):
            enemy_ptr = self._m.resolve_ptr_list(self._enemy_vector_ptr, [i * self._m.ptr_size])
            enemies.append(Player(enemy_ptr, self._m))
        return enemies

    def _get_window_dims(self):
        width = self._m.read_mem('u32', self._window_width_ptr)
        height = self._m.read_mem('u32', self._window_height_ptr)
        return width, height

    def update_esp(self):
        while states['esp'] != 0:
            enemies = filter(lambda x: x.is_alive(), self._get_enemies())
            for enemy in enemies:
                f, h, should_draw = self.object_to_screen(enemy)
                if should_draw:
                    self._m.add_rect({'x1': f[0], 'y1': f[1], 'x2': h[0], 'y2': h[1]})
            self._m.draw_esp()

    def toggle_esp(self):
        status = self._m.toggle_esp()
        if status is True and states['esp'] == 0:
            print('[+] ESP on')
            p = Thread(target=self.update_esp)
            states['esp'] = p
            p.start()
        else:
            print('[-] ESP off')
            p = states['esp']
            states['esp'] = 0
            p.join()

    def calc_bounding_box(self, player):
        hx, hy, _ = player.get_position('head')
        fx, fy, _ = player.get_position('foot')
        width = abs(hy - fy) / 2
        rect = {}
        rect['x1'] = hx - width
        rect['y1'] = hy
        rect['x2'] = fx + width
        rect['y2'] = fy
        return rect

    def get_distance(self, enemy):
        px, py, pz = self.player.get_position('head')
        ex, ey, ez = enemy.get_position('head')
        euclidean_dist = math.sqrt(math.pow(ex - px, 2) + math.pow(ey - py, 2))
        return euclidean_dist

    def calc_aim_angles(self, enemy):
        px, py, pz = self.player.get_position('head')
        ex, ey, ez = enemy.get_position('head')
        euclidean_dist = self.get_distance(enemy)

        # calculate pitch:  tan-inv(dz/hypoteneuse)
        pitch = -math.degrees(math.atan2(pz - ez, euclidean_dist))

        # calculate yaw: tan-inv(dy/dx)
        yaw = math.degrees(math.atan2(py - ey, px - ex))

        return pitch, yaw - 90

    def trace_line(self, enemy):
        px, py, pz = map(lambda x: struct.pack('<f', x), self.player.get_position('head'))
        ex, ey, ez = map(lambda x: struct.pack('<f', x), enemy.get_position('head'))
        px, py, pz = map(lambda x: struct.unpack('<I', x)[0], [px, py, pz])
        ex, ey, ez = map(lambda x: struct.unpack('<I', x)[0], [ex, ey, ez])
        player_obj = self._m.read_mem('u32', self._player_ptr)
        is_visible = self._m.trace_line(px, py, pz, ex, ey, ez, player_obj)

        # if traceline returns 0, then we can see the player
        return struct.unpack('<b', is_visible)[0] == 0

    def toggle_aimbot(self):
        if states['aimbot'] == 0:
            print('[*] Aimbot on')
            p = Thread(target=self.aim)
            states['aimbot'] = p
            p.start()
        else:
            print('[*] Aimbot off')
            p = states['aimbot']
            states['aimbot'] = 0
            p.join()

    def aim(self):
        while states['aimbot'] != 0:
            enemies = self._get_enemies()
            enemies = filter(lambda x: x.is_alive(), enemies)
            enemies = list(filter(self.trace_line, enemies))
            dist = list(map(self.get_distance, enemies))
            if len(enemies) > 0:
                idx = dist.index(min(dist))
                closest = enemies[idx]
                pitch, yaw = self.calc_aim_angles(closest)
                self.player.pitch = pitch - 5
                self.player.yaw = yaw

    def object_to_screen(self, player):
        # read mvp matrix (model view projection) to convert from
        # object to clip coordinates
        view_matrix = self._read_view_matrix().transpose()
        vec3_f = player.get_position('foot') + (1,)
        vec3_h = player.get_position('head') + (1,)
        vec3_f = np.matrix(vec3_f).transpose()
        vec3_h = np.matrix(vec3_h).transpose()
        pos_f = np.dot(view_matrix, vec3_f)
        pos_h = np.dot(view_matrix, vec3_h)
        w_f = pos_f.item(-1)
        w_h = pos_h.item(-1)

        # convert to normalized device coordinates
        ndc_f = pos_f / pos_f.item(-1)
        ndc_h = pos_h / pos_h.item(-1)

        cam_x, cam_y = map(lambda x: x / 2, self._get_window_dims())

        # convert to onscreen coordinates
        x_f = cam_x * ndc_f.item(0) + cam_x
        y_f = cam_y - cam_y * ndc_f.item(1)
        x_h = cam_x * ndc_h.item(0) + cam_x
        y_h = cam_y - cam_y * ndc_h.item(1)

        return (x_f, y_f), (x_h, y_h), (w_f > 0.1) and (w_h > 0.1)

menu = '''

****************************
    1. Set Health to 999
    2. Set Clip to 999
    3. Set Ammo to 999
    4. Toggle ESP
    5. Toggle Aimbot
****************************

'''

trainer = Trainer(sys.argv[1])
states = {
    'aimbot': 0,
    'esp': 0
}
def main():
    while True:
        print(menu)
        choice = int(input('> '))

        if choice not in range(1, 6):
            print('Invalid Option!')
            continue

        if choice == 1:
            trainer.player.health = 999
        elif choice == 2:
            trainer.player.clip = 999
        elif choice == 3:
            trainer.player.ammo = 999
        elif choice == 4:
            trainer.toggle_esp()
        elif choice == 5:
            trainer.toggle_aimbot()
        else:
            pass

if __name__ == '__main__':
    # trainer._m.test_draw()
    # embed()
    main()
