class ProgramTextWriter:
    def __init__(self):
        pass

    # HTML tags
    BEGIN_ANCHOR = "<A NAME=\""
    END_ANCHOR = "\"></A>"
    BYTES_DELIM = ""
    STRUCT_PREFIX = "|_"
    INDENT_SPACES = 3

    def __init__(self, file, program, address_set_view, task_monitor, options):
        self.options = options
        # Exit if options are INVALID
        len = (options.addr_width + options.bytes_width +
               options.pre_mnemonic_width + options.mnemonic_width +
               options.operand_width) - 1

    def process(self):
        writer = None
        buffy = StringBuilder()

        while True:
            current_code_unit = self.get_current_code_unit()
            if not address_set_view.contains(current_address):
                continue

            # Process the labels and refs...
            pre_symbol_width = options.addr_width + options.bytes_width
            back_ref_empty_flag = 0
            while len(symbol_lines) > 0 or has_more_lines(back_rl_d) or has_more_lines(fwd_rl_d):
                buffy = StringBuilder()
                if not symbol_lines.empty():
                    buffy.append(gen_fill(pre_symbol_width))
                    buffy.append(clip(symbol_lines.remove(0), options.label_width, True, True))
                else:
                    back_ref_empty_flag += 1
                if has_more_lines(back_rl_d) and len > 0:
                    buffy.append(fwd_rl_d.get_next_line())
                elif not symbol_lines.empty():
                    buffy.append(gen_fill(options.addr_width + options.bytes_width))

            writer.println(buffy.toString())

        # End of line area...
    def get_current_code_unit(self):
        pass

    def process_address(self, cu_address, prefix=None):
        if prefix is None:
            return
        width = self.options.get_addr_width()
        addr_str = str(cu_address)
        buffy.append(clip(addr_str, width - 1, True, False))

    # Process the bytes...
    def process_bytes(self, code_unit):
        width = options.bytes_width
        if width < 1:
            return

        try:
            byte_array = code_unit.get_bytes()
            for i in range(len(byte_array)):
                buffy.append(clip(str(hex(int.from_bytes([byte_array[i]], 'big')), width - len(str(cu_address)) + 2, True, False))
        except MemoryAccessException as mae:
            pass

    # Process the operand...
    def process_operand(self, code_unit):
        if isinstance(code_unit, Instruction):
            op_count = code_unit.get_num_operands()
            for i in range(op_count - 1):
                buffy.append(clip(str(cu_address), width - len(str(cu_address)) + 2, True, False))
    # Process the subdata...
    def process_sub_data(self, data, indent_level=0, cu_format=None):
        if isinstance(data, Data) and not data.get_num_components() > 1:
            return

        for i in range(len(components)):
            component = components[i]
            buffy.append(gen_fill(indent_level * INDENT_SPACES))
    # Process the plate...
    def process_plate(self, code_unit, plate):
        if isinstance(code_unit, Data) and not data.get_num_components() > 1:
            return

        for i in range(len(plate)):
            s = clip(str(component), width - len(str(cu_address)) + 2, True, False)
    # Process the space...
    def process_space(self):
        pass
