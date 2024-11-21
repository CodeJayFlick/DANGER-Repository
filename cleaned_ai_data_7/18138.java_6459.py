class RleDecoder:
    def __init__(self):
        self.config = TSFileDescriptor.getInstance().getConfig()
        self.mode = None
        self.bit_width = 0
        self.current_count = 0
        self.length = 0
        self.is_length_and_bit_width_readed = False
        self.byte_cache = bytearray(0)
        self.bit_packing_num = 0

    def reset(self):
        self.current_count = 0
        self.is_length_and_bit_width_readed = False
        self.bit_packing_num = 0
        self.byte_cache = bytearray(0)

    def get_header(self, byte_buffer):
        header = ReadWriteForEncodingUtils.read_unsigned_var_int(byte_buffer)
        if (header & 1) == 0:
            self.mode = "RLE"
        else:
            self.mode = "BIT_ PACKED"
        return header

    def read_next(self, byte_buffer):
        header = get_header(byte_buffer)
        if self.mode == "RLE":
            self.current_count = (header >> 1)
            self.read_number_in_rle()
        elif self.mode == "BIT_PACKED":
            self.call_read_bit_packing_buffer(header)

    def call_read_bit_packing_buffer(self, header):
        bit_packed_group_count = (header >> 1)
        last_bit_packed_num = ReadWriteIOUtils.read(byte_buffer)
        if bit_packed_group_count > 0:
            self.current_count = (bit_packed_group_count - 1) * TSFileConfig.RLE_MIN_REPEATED_NUM + last_bit_packed_num
            self.bit_packing_num = self.current_count
        else:
            raise TsFileDecodingException(f"tsfile-encoding IntRleDecoder: bitPackedGroupCount {bit_packed_group_count}, smaller than 1")
        self.read_bit_packing_buffer(bit_packed_group_count, last_bit_packed_num)

    def read_length_and_bit_width(self, byte_buffer):
        self.length = ReadWriteForEncodingUtils.read_unsigned_var_int(byte_buffer)
        tmp = bytearray(self.length)
        byte_buffer.get(tmp, 0, self.length)
        self.byte_cache = memoryview(tmp)
        self.is_length_and_bit_width_readed = True
        self.bit_width = ReadWriteIOUtils.read(self.byte_cache)

    def read_number_in_rle(self):
        pass

    def call_read_bit_packing_buffer(self, bit_packed_group_count, last_bit_packed_num):
        pass

    def init_packer(self):
        pass

    def has_next(self, byte_buffer):
        if self.current_count > 0 or byte_buffer.nbytes > 0:
            return True
        else:
            return False

    def read_boolean(self, byte_buffer):
        raise TsFileDecodingException("Method readBoolean is not supported by RleDecoder")

    def read_short(self, byte_buffer):
        raise TsFileDecodingException("Method readShort is not supported by RleDecoder")

    def read_int(self, byte_buffer):
        raise TsFileDecodingException("Method readInt is not supported by RleDecoder")

    def read_long(self, byte_buffer):
        raise TsFileDecodingException("Method readLong is not supported by RleDecoder")

    def read_float(self, byte_buffer):
        raise TsFileDecodingException("Method readFloat is not supported by RleDecoder")

    def read_double(self, byte_buffer):
        raise TsFileDecodingException("Method readDouble is not supported by RleDecoder")

    def read_binary(self, byte_buffer):
        raise TsFileDecodingException("Method readBinary is not supported by RleDecoder")

    def read_big_decimal(self, byte_buffer):
        raise TsFileDecodingException("Method readBigDecimal is not supported by RleDecoder")
