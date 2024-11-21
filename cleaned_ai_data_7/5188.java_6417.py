class Relocation:
    def __init__(self):
        self.opcode = None

    def is_match(self):
        pass  # abstract method in Python; needs to be implemented by subclasses

    def apply(self, import_state_cache=None, reloc_state=None, header=None, program=None, log=None, monitor=None):
        pass  # abstract method in Python; needs to be implemented by subclasses

    @property
    def opcode(self):
        return self.opcode

    @opcode.setter
    def opcode(self, value):
        self.opcode = value

    @property
    def size_in_bytes(self):
        return 2

    def to_data_type(self) -> dict:
        dt = {"WORD": 4, "DWORD": 8}[self.size_in_bytes]
        return {
            "name": str(self),
            "data_type": dt,
        }

    def __str__(self):
        class_name = self.__class__.__name__
        pos = class_name.rfind('.')
        if pos == -1:
            return class_name
        return class_name[pos+1:]
