class LocalVariableJava:
    def __init__(self):
        self.startPC = 0
        self.length = 0
        self.nameIndex = 0
        self.descriptorIndex = 0
        self.index = 0

    def read_from_binary(self, reader):
        try:
            self.startPC = reader.read_short()
            self.length = reader.read_short()
            self.nameIndex = reader.read_short()
            self.descriptorIndex = reader.reader.read_short()
            self.index = reader.read_short()
        except Exception as e:
            print(f"Error reading from binary: {e}")

    def get_start_pc(self):
        return self.startPC & 0xffff

    def get_length(self):
        return self.length & 0xffff

    def get_name_index(self):
        return self.nameIndex & 0xffff

    def get_descriptor_index(self):
        return self.descriptorIndex & 0xffff

    def get_index(self):
        return self.index & 0xffff
