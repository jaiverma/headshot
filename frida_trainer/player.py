import scan


class Player:
    def __init__(self, ptr, mem_helper):
        self._ptr = ptr
        self._offsets = {
             'health': [0xf8],
             'weapon_ammo': [0x374, 0x10, 0x0],
             'weapon_clip': [0x374, 0x14, 0x0],
             'player_name': [0x225],
             'head_vector3f': [0x4],
             'foot_vector3f': [0x34],
             'yaw': [0x40],
             'pitch': [0x44]
         }
        self._m = mem_helper
        self.name = self._m.read_mem('s', self._m.resolve_ptr_list(self._ptr, self._offsets['player_name']))

    @property
    def health(self):
        health_addr = self._m.resolve_ptr_list(self._ptr, self._offsets['health'])
        if health_addr < 0x1000:
             return -1, -1
        return health_addr, self._m.read_mem('s32', health_addr)

    @health.setter
    def health(self, new_health):
        health_addr, cur_health = self.health
        print('[*] Current health: {}'.format(cur_health))
        print('[+] Overwriting with: {}'.format(new_health))
        self._m.write_mem('u32', health_addr, new_health)
        _, cur_health = self.health
        print('[*] New health: {}'.format(cur_health))

    @property
    def clip(self):
        clip_addr = self._m.resolve_ptr_list(self._ptr, self._offsets['weapon_clip'])
        return clip_addr, self._m.read_mem('u32', clip_addr)

    @clip.setter
    def clip(self, new_clip):
        clip_addr, cur_clip = self.clip
        print('[*] Current clip: {}'.format(cur_clip))
        print('[+] Overwriting with: {}'.format(new_clip))
        self._m.write_mem('u32', clip_addr, new_clip)
        _, cur_clip = self.clip
        print('[*] New clip: {}'.format(cur_clip))

    @property
    def ammo(self):
        ammo_addr = self._m.resolve_ptr_list(self._ptr, self._offsets['weapon_ammo'])
        return ammo_addr, self._m.read_mem('u32', ammo_addr)

    @ammo.setter
    def ammo(self, new_ammo):
        ammo_addr, cur_ammo = self.ammo
        print('[*] Current ammo: {}'.format(cur_ammo))
        print('[+] Overwriting with: {}'.format(new_ammo))
        self._m.write_mem('u32', ammo_addr, new_ammo)
        _, cur_ammo = self.ammo
        print('[*] New ammo: {}'.format(cur_ammo))

    @property
    def pitch(self):
        pitch_addr = self._m.resolve_ptr_list(self._ptr, self._offsets['pitch'])
        return pitch_addr, self._m.read_mem('f', pitch_addr)

    @pitch.setter
    def pitch(self, new_pitch):
        pitch_addr, cur_pitch = self.pitch
        print('[*] Current pitch: {}'.format(cur_pitch))
        print('[+] Overwriting with: {}'.format(new_pitch))
        self._m.write_mem('f', pitch_addr, new_pitch)
        _, cur_pitch = self.pitch
        print('[*] New pitch: {}'.format(cur_pitch))

    @property
    def yaw(self):
        yaw_addr = self._m.resolve_ptr_list(self._ptr, self._offsets['yaw'])
        return yaw_addr, self._m.read_mem('f', yaw_addr)

    @yaw.setter
    def yaw(self, new_yaw):
        yaw_addr, cur_yaw = self.yaw
        print('[*] Current yaw: {}'.format(cur_yaw))
        print('[+] Overwriting with: {}'.format(new_yaw))
        self._m.write_mem('f', yaw_addr, new_yaw)
        _, cur_yaw = self.yaw
        print('[*] New yaw: {}'.format(cur_yaw))

    def get_position(self, location='head'):
        assert location in ['head', 'foot']
        position_ptr = self._m.resolve_ptr_list(self._ptr, self._offsets['{}_vector3f'.format(location)])
        x = self._m.read_mem('f', position_ptr)
        y = self._m.read_mem('f', position_ptr + scan.mem_types['f'][1])
        z = self._m.read_mem('f', position_ptr + scan.mem_types['f'][1] * 2)
        return x, y, z

    def is_alive(self):
        _, player_health = self.health
        return (player_health > 0) and (player_health <= 100)
