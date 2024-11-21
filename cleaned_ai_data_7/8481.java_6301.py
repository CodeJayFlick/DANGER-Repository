class PointerMsType:
    PDB_ID = 0x1002

    def __init__(self):
        self.is_restrict = False
        self.size = None
        self.is_mocom = False
        self.is_lref = False
        self.is_rref = False
        self.unk = False

    @property
    def is_restrict(self):
        return self.is_restrict

    @is_restrict.setter
    def is_restrict(self, value):
        self.is_restrict = value

    @property
    def is_mocom(self):
        return self.is_mocom

    @is_mocom.setter
    def is_mocom(self, value):
        self.is_mocom = value

    @property
    def is_lref(self):
        return self.is_lref

    @is_lref.setter
    def is_lref(self, value):
        self.is_lref = value

    @property
    def is_rref(self):
        return self.is_rref

    @is_rref.setter
    def is_rref(self, value):
        self.is_rref = value

    @property
    def unk(self):
        return self.unk

    @unk.setter
    def unk(self, value):
        self.unk = value

    def parse_attributes(self, reader):
        attributes = reader.parse_unsigned_int_val()
        pointer_type = (attributes & 0x001f)
        attributes >>= 5
        pointer_mode = (attributes & 0x0007)
        attributes >>= 3

        is_flat = ((attributes & 0x0001) == 0x0001)
        attributes >>= 1
        is_volatile = ((attributes & 0x0001) == 0x0001)
        attributes >>= 1
        is_const = ((attributes & 0x0001) == 0x0001)
        attributes >>= 1
        is_unaligned = ((attributes & 0x0001) == 0x0001)
        attributes >>= 1
        self.is_restrict = ((attributes & 0x0001) == 0x0001)
        attributes >>= 1

        self.size = (attributes & 0x003f)
        attributes >>= 6

        self.is_mocom = ((attributes & 0x0001) == 0x0001)
        attributes >>= 1
        self.is_lref = ((attributes & 0x0001) == 0x0001)
        attributes >>= 1
        self.is_rref = ((attributes & 0x0001) == 0x0001)
        attributes >>= 1
        self.unk = ((attributes & 0x0001) == 0x0001)

    def get_my_size(self):
        return self.size

class AbstractPdb:
    pass

class PdbByteReader:
    def parse_unsigned_int_val(self):
        # implementation of this method is missing in the given Java code
        pass

def main():
    pdb = AbstractPdb()
    reader = PdbByteReader()
    pointer_ms_type = PointerMsType()

    try:
        pointer_ms_type.parse_attributes(reader)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
