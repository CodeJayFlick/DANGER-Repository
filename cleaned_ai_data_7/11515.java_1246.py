class PcodeEmitPacked:
    unimpl_tag = 0x20
    inst_tag = 0x21
    op_tag = 0x22
    void_tag = 0x23
    spaceid_tag = 0x24
    addrsz_tag = 0x25
    end_tag = 0x60

    class LabelRef:
        def __init__(self, op_index, label_index, label_size, streampos):
            self.opIndex = op_index
            self.labelIndex = label_index
            self.labelSize = label_size
            self.streampos = streampos

    def __init__(self):
        self.buf = PackedBytes(64)

    def __init__(self, walk, ictx, fallOffset, override, uniqueFactory):
        super().__init__(walk, ictx, fallOffset, override, uniqueFactory)
        self.buf = PackedBytes(512)

    @property
    def packed_bytes(self):
        return self.buf

    def resolve_relatives(self):
        if not hasattr(self, 'labelref'):
            return
        for i in range(len(self.labelref)):
            ref = self.labelref[i]
            if (ref.labelIndex >= len(labeldef) or labeldef[ref.labelIndex] is None):
                raise SleighException("Reference to non-existent sleigh label")
            res = long(labeldef[ref.labelIndex]) - long(ref.opIndex)
            if ref.labelSize < 8:
                mask = -1
                mask >>= (8 - ref.labelSize) * 8
                res &= mask
            self.insert_offset(ref.streampos + 5, res)

    def add_label_ref(self):
        if not hasattr(self, 'labelref'):
            self.labelref = []
        label_index = int(incache[0].offset)
        label_size = incache[0].size
        # Force the emitter to write out a maximum length encoding (12 bytes) of a long
        # so that we have space to insert whatever value we need to when this relative is resolved
        incache[0].offset = -1

        self.labelref.append(LabelRef(numOps, label_index, label_size, len(self.buf)))

    def dump(self, instr_addr, opcode, in_, isize, out_):
        opcode = check_overrides(opcode, in_)
        check_overlays(opcode, in_, isize, out_)
        self.buf.write(op_tag)
        self.buf.write(opcode + 0x20)
        if out_ is None:
            self.buf.write(void_tag)
        else:
            dump_varnode_data(out_)
        i = 0
        if opcode == PcodeOp.LOAD or opcode == PcodeOp.STORE:
            dump_space_id(in_[0])
            i += 1
        for _ in range(i, isize):
            dump_varnode_data(in[_])

    def write(self, val):
        self.buf.write(val)

    @staticmethod
    def dump_offset(val):
        while val != 0:
            chunk = int((val & 0x3f))
            val >>= 6
            yield chunk + 0x20

    def insert_offset(self, streampos, val):
        while val != 0:
            if self.buf.get_byte(streampos) == end_tag:
                raise SleighException("Could not properly insert relative jump offset")
            chunk = int((val & 0x3f))
            val >>= 6
            self.buf.insert_byte(streampos, chunk + 0x20)
            streampos += 1

    def dump_space_id(self, v):
        self.buf.write(spaceid_tag)
        spcindex = ((v.offset >> AddressSpace.ID_UNIQUE_SHIFT) & 0xFFFFFF)
        self.buf.write(spcindex + 0x20)

    @staticmethod
    def dump_varnode_data(v):
        self.buf.write(addrsz_tag)
        spcindex = v.space.get_unique()
        self.buf.write(spcindex + 0x20)
        yield from PcodeEmitPacked.dump_offset(v.offset)
        self.buf.write((v.size & 0xFFFFFF) + 0x20)

class PackedBytes:
    def __init__(self, size):
        self.data = bytearray(size)

    @property
    def byte(self):
        return bytes(self.data[:1])

    def write(self, val):
        self.data.extend([val >> 5])
        self.data.append(val & 0x1F)

    def get_byte(self, pos):
        if pos >= len(self.data):
            raise SleighException("Index out of range")
        return int.from_bytes(self.data[pos:pos+1], 'big')

    def insert_byte(self, pos, val):
        self.data.insert(pos, bytes([val >> 5]))
        self.data.insert(pos + 1, bytes([(val & 0x1F)]))
