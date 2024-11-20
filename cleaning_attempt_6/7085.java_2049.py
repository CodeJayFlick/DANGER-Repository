class CDexCodeItem:
    kRegistersSizeShift = 12
    kInsSizeShift = 8
    kOutsSizeShift = 4
    kTriesSizeSizeShift = 0
    kInsnsSizeShift = 5

    kBitPreHeaderRegisterSize = 0
    kBitPreHeaderInsSize = 1
    kBitPreHeaderOutsSize = 2
    kBitPreHeaderTriesSize = 3
    kBitPreHeaderInsnsSize = 4
    kFlagPreHeaderRegisterSize = (1 << kBitPreHeaderRegisterSize)
    kFlagPreHeaderInsSize = (1 << kBitPreHeaderInsSize)
    kFlagPreHeaderOutsSize = (1 << kBitPreHeaderOutsSize)
    kFlagPreHeaderTriesSize = (1 << kBitPreHeaderTriesSize)
    kFlagPreHeaderInsnsSize = (1 << kBitPreHeaderInsnsSize)

    kFlagPreHeaderCombined = (
        kFlagPreHeaderRegisterSize | 
        kFlagPreHeaderInsSize |
        kFlagPreHeaderOutsSize |
        kFlagPreHeaderTriesSize |
        kFlagPreHeaderInsnsSize
    )

    def __init__(self, reader):
        super().__init__()
        
        self.start_index = reader.get_pointer_index()
        
        # Packed code item data,
        # 4 bits each: [registers_size, ins_size, outs_size, tries_size]
        self.fields_ = reader.read_next_short()

        self.registersSize = (self.fields_ >> kRegistersSizeShift) & 0xf
        self.incomingSize = (self.fields_ >> kInsSizeShift) & 0xf
        self.outgoingSize = (self.fields_ >> kOutsSizeShift) & 0xf
        self.triesSize = (self.fields_ >> kTriesSizeSizeShift) & 0xf

        # 5 bits, if either of the fields required preheader extension,
        # 11 bits for the number of instruction code units.
        self.insns_count_and_flags_ = reader.read_next_short()

        self.instructionSize = (self.insns_count_and_flags_ >> kInsnsSizeShift)

        if self.has_pre_header():
            if self.has_pre_header(kFlagPreHeaderInsnsSize):
                self.start_index -= 2
                self.instructionSize += reader.read_short(self.start_index)
                self.start_index -= 2
                self.instructionSize += (reader.read_short(self.start_index) << 16)

            if self.has_pre_header(kFlagPreHeaderRegisterSize):
                self.start_index -= 2
                self.registersSize += reader.read_short(self.start_index)

            if self.has_pre_header(kFlagPreHeaderInsSize):
                self.start_index -= 2
                self.incomingSize += reader.read_short(self.start_index)

            if self.has_pre_header(kFlagPreHeaderOutsSize):
                self.start_index -= 2
                self.outgoingSize += reader.read_short(self.start_index)

            if self.has_pre_header(kFlagPreHeaderTriesSize):
                self.start_index -= 2
                self.triesSize += reader.read_short(self.start_index)

        if self.get_instruction_size() == 0:
            self.instruction_bytes = bytearray(0)
            self.instructions = []
        else:
            self.instruction_bytes = reader.read_next_bytearray(self.get_instruction_size() * 2)
            self.instructions = reader.read_next_short_array(self.get_instruction_size())

    def has_pre_header(self):
        return (self.insns_count_and_flags_ & kFlagPreHeaderCombined) != 0

    def has_pre_header(self, flag):
        return (self.insns_count_and_flags_ & flag) != 0

    @property
    def to_data_type(self):
        name = "cdex_code_item_" + str(self.get_instruction_size() * 2)
        structure = StructureDataType(name, 0)
        structure.add(WORD, "fields_", None)
        structure.add(WORD, "insns_count_and_flags_", None)

        if self.get_instruction_size() > 0:
            structure.add(ArrayDataType(WORD, self.get_instruction_size(), WORD.length), "insns_", None)

        structure.set_category_path(CategoryPath("/dex/cdex_code_item"))
        return structure
