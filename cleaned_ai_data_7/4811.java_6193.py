class DyldCacheImageInfo:
    def __init__(self):
        self.address = 0
        self.mod_time = 0
        self.inode = 0
        self.path_file_offset = 0
        self.pad = 0
        self.path = ""

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

    @property
    def mod_time(self):
        return self._mod_time

    @mod_time.setter
    def mod_time(self, value):
        self._mod_time = value

    @property
    def inode(self):
        return self._inode

    @inode.setter
    def inode(self, value):
        self._inode = value

    @property
    def path_file_offset(self):
        return self._path_file_offset

    @path_file_offset.setter
    def path_file_offset(self, value):
        self._path_file_offset = value

    @property
    def pad(self):
        return self._pad

    @pad.setter
    def pad(self, value):
        self._pad = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value

def create_dyld_cache_image_info(reader):
    dyld_cache_image_info = DyldCacheImageInfo()
    try:
        dyld_cache_image_info.address = reader.read_long()
        dyld_cache_image_info.mod_time = reader.read_long()
        dyld_cache_image_info.inode = reader.read_long()
        dyld_cache_image_info.path_file_offset = reader.read_int()
        dyld_cache_image_info.pad = reader.read_int()

        path_length = reader.read_int()
        if path_length > 0:
            dyld_cache_image_info.path = reader.read_string(path_length)
    except Exception as e:
        print(f"Error creating DYLD cache image info: {e}")
