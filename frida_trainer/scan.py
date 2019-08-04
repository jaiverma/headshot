import frida
import struct
from copy import deepcopy
import codecs
from curses import wrapper

with open('scan.js') as f:
    script = f.read()

mem_types = {
    'u32': ('<I', 4), # unsigned int (4 bytes)
    's32': ('<i', 4), # signed int (4 bytes)
    'u64': ('<Q', 8), # unsigned long (8 bytes)
    's64': ('<q', 8), # signed long (8 bytes)
    'f'  : ('<f', 4), # float (4 bytes)
    'd'  : ('<d', 8)  # double (8 byte)
}

def format_needle(mem_type, needle):
    if mem_type == 's':
        s = needle.encode().hex()
    else:
        s = struct.pack(mem_types[mem_type][0], needle)
        s = codecs.encode(s, 'hex').decode()

    s = iter(s)
    return ' '.join(i + j for i, j in zip(s, s))

class Mem:
    def __init__(self, pid):
        self.session = frida.get_usb_device().attach(pid)
        self.script = self.session.create_script(script)
        self.script.load()
        self.modules = self.script.exports.enumerate_modules()
        self.ptr_size = self.script.exports.ptr_size()
        self._interrupted = False

    def read_mem(self, mem_type, addr):
        if mem_type == 's':
            data = ''
            string = b''
            while data != b'\x00':
                data = self.script.exports.read_mem(addr, 1)
                string += data
                addr += 1

            try:
                string = string.decode().strip('\x00')
                return string
            except UnicodeDecodeError:
                return string[:-1]

        data = self.script.exports.read_mem(addr, mem_types[mem_type][1])
        return struct.unpack(mem_types[mem_type][0], data)[0]

    def write_mem(self, mem_type, addr, data):
        # data = list(struct.pack(mem_types[mem_type][0], data))
        data = format_needle(mem_type, data)
        data = list(map(lambda x: int(x, 16), data.split()))
        self.script.exports.write_mem(addr, data)

    def search_mem(self, mem_type, needle, haystack=None):
        needle = format_needle(mem_type, needle)
        if haystack is None:
            return self.script.exports.search_mem(needle)
        return self.script.exports.search_mem(needle, haystack)

    def get_module(self, name):
        for module in self.modules:
            if name == module['name']:
                # rename 'base' to 'address'
                # so that it can be used as a `haystack`
                m = deepcopy(module)
                m['address'] = m.pop('base')
                return m

    def get_ranges(self, module, protection=None):
        if protection is None:
            ranges = map(deepcopy, self.script.exports.enumerate_ranges(module['name']))
        else:
            ranges = map(deepcopy, self.script.exports.enumerate_ranges(module['name'], protection))
        ranges = list(ranges)

        for r in ranges:
            r['address'] = r.pop('base')
        return ranges

    def resolve_ptr_list(self, addr, ptr_list):
        for offset in ptr_list:
            ptr_format = 'u32' if self.ptr_size == 4 else 'u64'
            addr = self.read_mem(ptr_format, addr)
            addr += offset
        return addr

    def dump_region(self, mem_type, start_addr, n_elem, hexa=True, n_elem_in_line=3):
        def curse(stdscr):
            try:
                while True:
                    buf = []
                    cur_addr = start_addr
                    if mem_type is 'f':
                        hexa = False

                    for i in range(n_elem):
                        buf.append(self.read_mem(mem_type, cur_addr))
                        cur_addr += mem_types[mem_type][1]

                    cur_addr = start_addr
                    stdscr.clear()
                    for i in range(0, len(buf), n_elem_in_line):
                        data = buf[i:i + n_elem_in_line]
                        if hexa:
                            data = list(map(hex, data))
                        if mem_type is 'f':
                            data = list(map(lambda x: round(x, 2), data))
                        format_str = ['{:>8}'] * len(data)
                        data.extend(['-'] * (n_elem_in_line - len(data)))
                        stdscr.addstr('{} : '.format(hex(cur_addr)) + ' '.join(format_str).format(*data) + '\n')
                        cur_addr += mem_types[mem_type][1] * n_elem_in_line
                    stdscr.refresh()

            except KeyboardInterrupt:
                return

        wrapper(curse)

    ########################################################################
    # trainer speicific functions

    def toggle_esp(self):
        return self.script.exports.toggle_esp()

    def add_rect(self, rect):
        self.script.exports.add_rect(rect)

    def clear_rect(self):
        self.script.exports.clear_rect()

    def test_draw(self):
        self.script.exports.test_draw()

    def draw_esp(self):
        self.script.exports.draw_esp()

    def trace_line(self, from_x, from_y, from_z, to_x, to_y, to_z, p_tracer_ptr):
        return self.script.exports.trace_line(from_x, from_y, from_z, to_x, to_y, to_z, p_tracer_ptr)
