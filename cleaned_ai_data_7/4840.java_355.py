class DebugStateX86_32:
    def __init__(self):
        self.dr0 = 0
        self.dr1 = 0
        self.dr2 = 0
        self.dr3 = 0
        self.dr4 = 0
        self.dr5 = 0
        self.dr6 = 0
        self.dr7 = 0

    def from_binary_reader(self, reader):
        try:
            self.dr0 = int.from_bytes(reader.read(4), 'little')
            self.dr1 = int.from_bytes(reader.read(4), 'little')
            self.dr2 = int.from_bytes(reader.read(4), 'little')
            self.dr3 = int.from_bytes(reader.read(4), 'little')
            self.dr4 = int.from_bytes(reader.read(4), 'little')
            self.dr5 = int.from_bytes(reader.read(4), 'little')
            self.dr6 = int.from_bytes(reader.read(4), 'little')
            self.dr7 = int.from_bytes(reader.read(4), 'little')
        except Exception as e:
            print(f"Error: {e}")

    def to_data_type(self):
        try:
            struct = {'dr0': 0, 'dr1': 0, 'dr2': 0, 'dr3': 0, 'dr4': 0, 'dr5': 0, 'dr6': 0, 'dr7': 0}
            return struct
        except Exception as e:
            print(f"Error: {e}")
