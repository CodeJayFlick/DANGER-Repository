class Ext4XattrEntry:
    def __init__(self):
        self.e_name_len = None
        self.e_name_index = None
        self.e_value_offs = None
        self.e_value_block = None
        self.e_value_size = None
        self.e_hash = None
        self.e_name = None

    @property
    def e_name_len(self):
        return self._e_name_len

    @e_name_len.setter
    def e_name_len(self, value):
        self._e_name_len = value

    @property
    def e_name_index(self):
        return self._e_name_index

    @e_name_index.setter
    def e_name_index(self, value):
        self._e_name_index = value

    @property
    def e_value_offs(self):
        return self._e_value_offs

    @e_value_offs.setter
    def e_value_offs(self, value):
        self._e_value_offs = value

    @property
    def e_value_block(self):
        return self._e_value_block

    @e_value_block.setter
    def e_value_block(self, value):
        self._e_value_block = value

    @property
    def e_value_size(self):
        return self._e_value_size

    @e_value_size.setter
    def e_value_size(self, value):
        self._e_value_size = value

    @property
    def e_hash(self):
        return self._e_hash

    @e_hash.setter
    def e_hash(self, value):
        self._e_hash = value

    @property
    def e_name(self):
        return self._e_name

    @e_name.setter
    def e_name(self, value):
        self._e_name = value

    def is_end_of_list_marker(self):
        if (self.e_name_len == 0 and 
            self.e_name_index == 0 and 
            self.e_value_offs == 0 and 
            self.e_value_block == 0):
            return True
        else:
            return False

    def is_valid(self):
        if (0 <= self.e_name_index < len(Ext4Constants.EXT4_XATTR_NAMEINDEX_STRINGS)):
            return True
        else:
            return False

    def get_name(self):
        return Ext4Constants.EXT4_XATTR_NAMEINDEX_STRINGS[self.e_name_index] + \
               bytes(self._e_name).decode('utf-8')

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value


class Ext4Constants:
    EXT4_XATTR_NAMEINDEX_STRINGS = ["string1", "string2"]
