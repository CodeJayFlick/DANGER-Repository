class LSDATypeTable:
    def __init__(self):
        self.region = None
        self.next_address = None
        self.type_info_addrs = []

    def create(self, bottom: int, top: int) -> None:
        if not (bottom and top):
            return

        encoding = self.region.get_lsdatable().get_header().get_ttype_encoding()
        decoder = DwarfDecoderFactory.get_decoder(encoding)
        encoded_dt = decoder.get_data_type()
        stride = decoder.get_decode_size()

        comment = "Type Reference"
        top = align4(top)

        addr = bottom - (stride - 1)
        while addr >= top:
            ctx = DwarfDecodeContext(self.program, addr)
            try:
                type_ref = decoder.decode_address(ctx)
                self.type_info_addrs.append(type_ref)
                create_and_comment_data(self.program, addr, encoded_dt, comment, CodeUnit.EOL_COMMENT)

                if type_ref.get_offset() != 0:
                    self.program.reference_manager.add_memory_reference(addr, type_ref, RefType.DATA,
                        SourceType.ANALYSIS, 0)
            except MemoryAccessException as mae:
                SetCommentCmd(comment_cmd = new SetCommentCmd(addr, CodeUnit.EOL_COMMENT, "Unable to resolve pointer"))
                comment_cmd.apply_to(self.program)

            addr -= stride

        SetCommentCmd(comment_cmd = new SetCommentCmd(top, CodeUnit.PLATE_COMMENT, "(LSDA) Type Table"))
        comment_cmd.apply_to(self.program)
        self.next_address = bottom + 1

    def align4(self, addr: int):
        incr = 4 - ((addr % 4))
        if incr == 4:
            return addr
        create_and_comment_data(self.program, addr, ArrayDataType(ByteDataType(), incr, 1), " -- alignment pad", CodeUnit.EOL_COMMENT)
        return addr + incr

    def get_type_info_address(self, index: int):
        if not (index > 0 and index <= len(self.type_info_addrs)):
            return Address.NO_ADDRESS
        return self.type_info_addrs[index - 1]

    def get_next_address(self) -> int:
        return self.next_address


class DwarfDecodeContext:
    pass

class ArrayDataType:
    pass

class ByteDataType:
    pass

class CodeUnit:
    EOL_COMMENT = ""
    PLATE_COMMENT = ""

class RefType:
    DATA = ""

class SourceType:
    ANALYSIS = ""

class Address:
    NO_ADDRESS = None
