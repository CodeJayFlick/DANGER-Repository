Here is the translation of the Java code into Python:

```Python
class VersionFileHandler:
    def __init__(self):
        self.version_files = []
        self.open_file_ix = -1
        self.buffer_map = {}
        self.original_buf_count = 0
        self.max_buf_count = 0
        self.original_file_id = None
        self.free_indexes = []

    def construct(self, bf_mgr, target_file_id, target_ver, orig_ver):
        try:
            for v in range(orig_ver, target_ver):
                if self.open_file_ix != -1:
                    version_files[self.open_file_ix].close()
                vf = VersionFile(bf_mgr.get_version_file(v))
                self.version_files.append(vf)
                self.open_file_ix += 1
                if self.open_file_ix == 0:
                    original_buf_count = vf.original_buffer_count
                    free_indexes = vf.free_index_list
                    names = vf.old_parameter_names
                    for i in range(len(names)):
                        orig_parms[names[i]] = vf.old_parameters[names[i]]
                    original_file_id = vf.original_file_id
                else:
                    if last_target_file_id != vf.original_file_id:
                        raise IOException("Incorrect version file - wrong file ID")
                last_target_file_id = vf.target_file_id
        except Exception as e:
            self.close()
            raise

    def close(self):
        try:
            if self.open_file_ix != -1 and self.version_files[self.open_file_ix]:
                self.version_files[self.open_file_ix].close()
        except IOException as e:
            pass

    @property
    def original_file_id(self):
        return self.original_file_id

    @property
    def free_index_list(self):
        return self.free_indexes

    def get_old_buffer(self, buf, index):
        try:
            vf_index = self.buffer_map[index]
            return self.version_files[vf_index].get_old_buffer(buf, index)
        except NoValueException as e:
            pass
        if array.binary_search(free_indexes, index) >= 0:
            buf.id = -1
            buf.empty = True
            buf.dirty = False
            return buf
        return None

    def get_reverse_mod_map_data(self):
        bit_map_size = (self.max_buf_count + 7) // 8
        data = [0] * bit_map_size
        excess = self.max_buf_count % 8
        if excess != 0:
            data[bit_map_size - 1] |= 255 << excess
        for index in self.buffer_map.keys():
            if index >= self.max_buf_count:
                print("VersionFileHandler: unexpected buffer index")
                continue
            set_map_data_bit(data, index)
        return data

    def get_forward_mod_map_data(self):
        bit_map_size = (self.original_buf_count + 7) // 8
        data = [0] * bit_map_size
        excess = self.original_buf_count % 8
        if excess != 0:
            data[bit_map_size - 1] |= 255 << excess
        for index in self.buffer_map.keys():
            if index < self.original_buf_count:
                set_map_data_bit(data, index)
        return data

    def set_map_data_bit(self, data, index):
        byte_offset = index // 8
        bit_mask = 1 << (index % 8)
        data[byte_offset] |= bit_mask

    @property
    def original_buffer_count(self):
        return self.original_buf_count

    def get_old_parameter_names(self):
        names = list(orig_parms.keys())
        return names

    def get_old_parameter(self, name):
        obj = orig_parms.get(name)
        if obj is None:
            raise NoSuchElementException()
        return int(obj)

class VersionFile:
    def __init__(self, vf):
        self.vf = vf
        self.original_buffer_count = 0
        self.free_index_list = []
        self.old_parameter_names = []
        self.old_parameters = {}

    @property
    def original_file_id(self):
        return self.vf.get_original_file_id()

    @property
    def target_file_id(self):
        return self.vf.get_target_file_id()

    def get_old_buffer(self, buf, index):
        # implement this method

class DataBuffer:
    def __init__(self):
        pass

    @property
    def id(self):
        return 0

    @id.setter
    def id(self, value):
        self._id = value

    @property
    def empty(self):
        return False

    @empty.setter
    def empty(self, value):
        self._empty = value

    @property
    def dirty(self):
        return True

    @dirty.setter
    def dirty(self, value):
        self._dirty = value

class IOException:
    pass

class NoSuchElementException(Exception):
    pass
```

Note: This translation is not perfect and some parts of the code may need to be adjusted according to your specific requirements.