class GnuVernaux:
    def __init__(self):
        self.vna_hash = 0
        self.vna_flags = 0
        self.vna_other = 0
        self.vna_name = 0
        self.vna_next = 0

    @property
    def hash(self):
        return self.vna_hash

    @hash.setter
    def hash(self, value):
        self.vna_hash = value

    @property
    def flags(self):
        return self.vna_flags

    @flags.setter
    def flags(self, value):
        self.vna_flags = value

    @property
    def other(self):
        return self.vna_other

    @other.setter
    def other(self, value):
        self.vna_other = value

    @property
    def name(self):
        return self.vna_name

    @name.setter
    def name(self, value):
        self.vna_name = value

    @property
    def next(self):
        return self.vna_next

    @next.setter
    def next(self, value):
        self.vna_next = value


def to_data_type():
    struct = {"vna_hash": "Hash value of dependency name", 
              "vna_flags": "Dependency specific information",
              "vna_other": "Unused", 
              "vna_name": "Dependency name string offset", 
              "vna_next": "Offset in bytes to next vernaux entry"}
    return struct
