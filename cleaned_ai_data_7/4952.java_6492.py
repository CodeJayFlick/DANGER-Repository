class OmfFileHeader:
    def __init__(self):
        self.object_name = None  # Name of the object module
        self.lib_module_name = None  # Name of the module (within a library)
        self.translator = None  # Usually the compiler/linker used to produce this object
        self.is_little_endian = False
        self.name_list = []  # Indexable List of segment, group, ... names
        self.segments = []  # List of segments in this file
        self.groups = []  # List of groups for this file
        self.extern_symbols = []  # List of symbols that are external to this file
        self.public_symbols = []  # List of symbols exported by this file
        self.fixups = []  # List of relocation records for this file

    def read_record_header(self, reader):
        pass  # Not implemented in Python equivalent

    def get_name(self):
        return self.object_name

    def get_library_module_name(self):
        return self.lib_module_name

    def get_machine_name(self):
        return "i386"  # This is the only possibility

    def get_translator(self):
        return self.translator

    def is_little_endian_(self):
        return self.is_little_endian

    def get_segments(self):
        return self.segments

    def get_extra_segments(self):
        return None  # Not implemented in Python equivalent

    def resolve_segment(self, index):
        pass  # Not implemented in Python equivalent

    def sort_segment_data_blocks(self):
        if self.extra_seg is not None:
            for i in range(len(self.extra_seg)):
                self.segments.append(self.extra_seg[i])
            for i in range(len(self.segments)):
                self.segments[i].sort_data()

    def add_enumerated_block(self, datablock):
        pass  # Not implemented in Python equivalent

    def evaluate_comdef(self, comdef):
        pass  # Not implemented in Python equivalent

class OmfRecord:
    @staticmethod
    def read_record(reader):
        pass  # Not implemented in Python equivalent

@staticmethod
def scan(reader, monitor, initial_comments_only):
    record = OmfRecord.read_record(reader)
    if (record.get_record_type() & 0xfc) != OMF_RECORD.THEADR:
        raise OmfException("Object file does not start with proper header")
    header = OmfFileHeader()
    last_data_block = None

    while True:
        record = OmfRecord.read_record(reader)
        if monitor.is_cancelled():
            break
        type = record.get_record_type() & 0xfe
        switch (type):
            case OMF_RECORD.COMENT:
                comment_class = ((OmfCommentRecord)record).get_comment_class()
                if comment_class == 0:
                    header.translator = ((OmfCommentRecord)record).get_value()
                elif comment_class == 0xA3:
                    header.lib_module_name = ((OmfCommentRecord)record).get_value()
            case OMF_RECORD.MODEND:
                # We are not currently examining the end module record
                break
            case OMF_RECORD.COMDEF or OMF_RECORD.LCOMDEF:
                header.evaluate_comdef((OmfComdefRecord)record)
                header.extern_symbols.append((OmfExternalSymbol)record)
            case OMF_RECORD.PUBDEF:
                header.public_symbols.append((OmfSymbolRecord)record)
            case OMF_RECORD.FIXUPP:
                fixup_rec = (OmfFixupRecord)record
                fixup_rec.set_data_block(last_data_block)
                header.fixups.append(fixup_rec)
            default:
                break

    return header

@staticmethod
def parse(reader, monitor):
    record = OmfRecord.read_record(reader)
    if (record.get_record_type() & 0xfc) != OMF_RECORD.THEADR:
        raise OmfException("Object file does not start with proper header")
    header = OmfFileHeader()
    last_data_block = None

    while True:
        record = OmfRecord.read_record(reader)
        if monitor.is_cancelled():
            break
        type = record.get_record_type() & 0xfe
        switch (type):
            case OMF_RECORD.COMENT:
                comment_class = ((OmfCommentRecord)record).get_comment_class()
                if comment_class == 0:
                    header.translator = ((OmfCommentRecord)record).get_value()
                elif comment_class == 0xA3:
                    header.lib_module_name = ((OmfCommentRecord)record).get_value()
            case OMF_RECORD.MODEND:
                # We are not currently examining the end module record
                break
            case OMF_RECORD.COMDEF or OMF_RECORD.LCOMDEF:
                header.evaluate_comdef((OmfComdefRecord)record)
                header.extern_symbols.append((OmfExternalSymbol)record)
            case OMF_RECORD.PUBDEF:
                header.public_symbols.append((OmfSymbolRecord)record)
            case OMF_RECORD.FIXUPP:
                fixup_rec = (OmfFixupRecord)record
                fixup_rec.set_data_block(last_data_block)
                header.fixups.append(fixup_rec)
            default:
                break

    return header

@staticmethod
def do_linking(start_address, segments):
    pass  # Not implemented in Python equivalent

@staticmethod
def check_magic_number(reader):
    first = reader.read_next_byte()
    if (first & 0xfc) != 0x80:
        return False
    len = reader.read_next_short() & 0xffff
    string_len = reader.read_next_byte() & 0xff
    if len != string_len + 2:
        return False
    return True

@staticmethod
def create_reader(provider):
    return BinaryReader(provider, True)
