class DWARFAttributeFactory:
    MAX_BLOCK4_SIZE = 1024 * 1024

    def __init__(self, prog):
        self.prog = prog

    def read(self, reader, unit, form) -> object:
        debug_strings = self.prog.get_debug_strings()
        
        if form == DWARFForm.DW_FORM_addr:
            return DWARFNumericAttribute(DWARFUtil.read_var_sized_ulong(reader, unit.pointer_size))
        
        elif form in [DWARFForm.DW_FORM_ref1, DWARFForm.DW_FORM_ref2, 
                       DWARFForm.DW_FORM_ref4, DWARFForm.DW_FORM_ref8]:
            uoffset = DWARFUtil.read_var_sized_ulong(reader, 2 if form == DWARFForm.DW_FORM_ref2 else 1)
            return DWARFNumericAttribute(uoffset + unit.start_offset)

        elif form in [DWARFForm.DW_FORM_ref_udata, DWARFForm.DW_FORM_ref_addr]:
            uoffset = LEB128.read_as_long(reader, False if form == DWARFForm.DW_FORM_ref_udata else True)
            return DWARFNumericAttribute(uoffset + unit.start_offset)

        elif form in [DWARFForm.DW_FORM_block1, DWARFForm.DW_FORM_block2]:
            length = DWARFUtil.read_var_sized_uint(reader, 1 if form == DWARFForm.DW_FORM_block1 else 2)
            return DWARFBlobAttribute(reader.read_next_byte_array(length))

        elif form in [DWARFForm.DW_FORM_block4]:
            length = DWARFUtil.read_var_sized_uint(reader, 4)
            if length < 0 or length > self.MAX_BLOCK4_SIZE:
                raise IOException("Invalid/bad dw_form_block4 size: " + str(length))
            return DWARFBlobAttribute(reader.read_next_byte_array(length))

        elif form == DWARFForm.DW_FORM_exprloc:
            length = LEB128.read_as_uint32(reader)
            if length < 0 or length > self.MAX_BLOCK4_SIZE:
                raise IOException("Invalid/bad dw_form_exprloc size: " + str(length))
            return DWARFBlobAttribute(reader.read_next_byte_array(length))

        elif form == DWARFForm.DW_FORM_flag:
            return DWARFBooleanAttribute(bool(reader.read_next_byte() != 0))

        elif form in [DWARFForm.DW_FORM_string, DWARFForm.DW_FORM_strp]:
            if form == DWARFForm.DW_FORM_strp:
                string_offset = DWARFUtil.read_offset_by_dwarf_format(reader, unit.format)
                if not debug_strings.is_valid(string_offset):
                    raise IOException("Bad string offset " + hex(string_offset))
                return DWARFDeferredStringAttribute(string_offset)

            else:  # form == DWARFForm.DW_FORM_string
                return DWARFStringAttribute(reader.read_next_null_terminated_ascii_string())

        elif form in [DWARFForm.DW_FORM_data1, DWARFForm.DW_FORM_data2, 
                      DWARFForm.DW_FORM_data4]:
            if form == DWARFForm.DW_FORM_data1:
                return DWARFAmbigNumericAttribute(reader.read_next_byte(), NumberUtil.UNSIGNED_BYTE_MASK)
            
            elif form in [DWARFForm.DW_FORM_data2, DWARFForm.DW_FORM_data4]:
                mask = NumberUtil.UNSIGNED_SHORT_MASK if form == DWARFForm.DW_FORM_data2 else NumberUtil.UNSIGNED_INT_MASK
                return DWARFAmbigNumericAttribute(reader.read_next_int(), mask)

        elif form in [DWARFForm.DW_FORM_sdata, DWARFForm.DW_FORM_udata]:
            return DWARFNumericAttribute(LEB128.read_as_long(reader, True if form == DWARFForm.DW_FORM_sdata else False))

        elif form == DWARFForm.DW_FORM_indirect:
            value_form = LEB128.read_as_uint32(reader)
            value = self.read(reader, unit, value_form)
            return DWARFIndirectAttribute(value, value_form)

        else:  # default
            raise ValueError("Unknown DWARF Form: " + str(form))
