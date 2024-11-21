class PrelinkMap:
    def __init__(self):
        self.map = {}

    def put(self, key, value):
        if isinstance(value, str) or isinstance(value, int) or isinstance(value, bool):
            self.map[key] = value

    def get_prelink_bundle_path(self):
        return self.map.get('PrelinkBundlePath', None)

    def get_prelink_uuid(self):
        return self.map.get('PrelinkUUID', None)

    def get_prelink_kmod_info(self):
        value = self.map.get('PrelinkKModInfo')
        if isinstance(value, int) and -1 <= value < 2**32:
            return value + 0xffffffff
        elif isinstance(value, int):
            return value + 0xffffffff
        else:
            return -1

    def get_prelink_executable(self):
        value = self.map.get('PrelinkExecutable')
        if isinstance(value, int) and -1 <= value < 2**32:
            return value + 0xffffffff
        elif isinstance(value, int):
            return value + 0xffffffff
        else:
            return -1

    def get_prelink_executable_size(self):
        value = self.map.get('PrelinkExecutableSize')
        if isinstance(value, int) and -1 <= value < 2**32:
            return value + 0xffffffff
        elif isinstance(value, int):
            return value + 0xffffffff
        else:
            return -1

    def get_prelink_executable_load_addr(self):
        value = self.map.get('PrelinkExecutableLoad')
        if isinstance(value, int) and -1 <= value < 2**32:
            return value + 0xffffffff
        elif isinstance(value, int):
            return value + 0xffffffff
        else:
            return -1

    def get_prelink_module_index(self):
        value = self.map.get('PrelinkModuleIndex')
        if isinstance(value, int) and -1 <= value < 2**32:
            return value + 0xffffffff
        elif isinstance(value, int):
            return value + 0xffffffff
        else:
            return -1

    def __str__(self):
        buffer = ''
        for key in sorted(self.map.keys()):
            if isinstance(self.map[key], int) and -1 <= self.map[key] < 2**32:
                buffer += f'{key}={hex(self.map[key]+0xffffffff)}\n'
            else:
                buffer += f'{key}={self.map[key]}\n'
        return buffer
