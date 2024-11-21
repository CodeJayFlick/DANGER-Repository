class OMFFileIndex:
    def __init__(self):
        self.cMod = None
        self.cRef = None
        self.modStart = []
        self.cRefCnt = []
        self.nameRef = []
        self.names = []

    @staticmethod
    def create_OMFFileIndex(reader, ptr):
        omf_file_index = OMFFileIndex()
        omf_file_index.init_OMFFileIndex(reader, ptr)
        return omf_file_index

    def init_OMFFileIndex(self, reader, ptr):
        index = ptr

        self.cMod = reader.read_short(index); index += 2
        self.cRef = reader.read_short(index); index += 2

        mod_start_length = int.from_bytes([self.cMod], byteorder='little')
        for i in range(mod_start_length):
            self.modStart.append(reader.read_short(index)); index += 2

        c_ref_cnt_length = int.from_bytes([self.cRef], byteorder='little')
        for i in range(c_ref_cnt_length):
            self.cRefCnt.append(reader.read_short(index)); index += 2

        name_ref_length = int.from_bytes([self.cRef], byteorder='little')
        for i in range(name_ref_length):
            self.nameRef.append(reader.read_int(index)); index += 4

        names_list = []
        for i in range(name_ref_length):
            name_index = index + self.nameRef[i]
            len_byte = reader.read_byte(name_index); name_index += 1
            length = int.from_bytes([len_byte], byteorder='little')
            name = reader.read_ascii_string(name_index, length).decode('ascii')
            names_list.append(name)
            index += (length + 1)

        self.names = list(names_list)


    def get_cMod(self):
        return self.cMod

    def get_cRef(self):
        return self.cRef

    def get_name_ref(self):
        return self.nameRef

    def get_names(self):
        return self.names

    def get_mod_start(self):
        return self.modStart

    def get_c_ref_cnt(self):
        return self.cRefCnt
