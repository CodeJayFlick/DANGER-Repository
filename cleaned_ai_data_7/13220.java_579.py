class JvmSwitchAnalyzer:
    ANALYZER_NAME = "JVM Switch Analyzer"
    ANALYZER_DESCRIPTION = "Disassembles jump targets of tableswitch and lookupswitch instructions"

    def __init__(self):
        pass

    def get_name(self):
        return self.ANALYZER_NAME

    def get_analysis_type(self):
        # This is equivalent to Java's enum, but Python doesn't have built-in support for enums.
        # So we'll just use a string constant
        return "INSTRUCTION_ANALYZER"

    def get_default_enablement(self, program):
        return True

    def get_description(self):
        return self.ANALYZER_DESCRIPTION

    def get_priority(self):
        return "DISASSEMBLY"

    def can_analyze(self, program):
        try:
            if JavaClassUtil.is_class_file(program):
                return True
        except Exception as e:
            pass  # Ignore exceptions for now
        return False

    def is_prototype(self):
        return False

    def analyze(self, program, set, monitor, log):
        monitor.set_maximum(set.get_num_addresses())
        monitor.set_progress(0)

        provider = MemoryByteProvider(program.memory(), program.min_address())
        reader = BinaryReader(provider, False)
        listing = program.listing()
        instruction_iterator = listing.instructions(set, True)

        while instruction_iterator.has_next():
            instruction = instruction_iterator.next()
            monitor.check_cancelled()
            monitor.increment_progress(instruction.length())

            mnemonic = instruction.mnemonic_string()

            if not (mnemonic == "tableswitch" or mnemonic == "lookupswitch"):
                continue  # Only care about switch instructions

            if len(instruction.mnemonic_references()) > 0:
                continue  # Analyzer has already handled this instruction

            monitor.set_message("JvmSwitchAnalyzer: {}".format(instruction.min_address()))

            if mnemonic == "tableswitch":
                self.process_table_switch(program, reader, instruction, monitor)
            else:
                self.process_lookup_switch(program, reader, instruction, monitor)

        return True

    def process_table_switch(self, program, reader, instruction, monitor):
        alignment_pad = Register("alignmentPad")
        alignment = int(instruction.value(alignment_pad, False))

        if len(instruction.op_objects(0)) == 0:
            Msg.info(self, "Skipping tableswitch instruction at {} - missing operand reference for default case.".format(instruction.address()))
            return

        op_objects = instruction.op_objects(0)
        default_address = instruction.operand_references(0)[0].to_address()
        low = int((Scalar(op_objects[1])).unsigned_value())
        high = int((Scalar(op_objects[2])).unsigned_value())

        addresses_to_disassemble = []

        # Handle the default case
        addresses_to_dissemble.append(default_address)
        self.add_label_and_reference(program, instruction, default_address, "default")

        base = instruction.memory().min_address().offset()
        index = instruction.min_address().offset()
        index -= base
        index += (1 + alignment + 4 + 4)  # tableswitch opcode + alignment + size of default + size of low + size of high

        reader.set_pointer_index(index)

        for i in range(low, high):
            try:
                offset = int(reader.read_next_int())
                address_to_disassemble = instruction.min_address().add(offset)
                addresses_to_dissemble.append(address_to_disassemble)
                label = "case_{}_(0x{})".format(low + i, hex(low + i))
                self.add_label_and_reference(program, instruction, address_to_disassemble, label)
            except IOException as e:
                Msg.error(self, str(e))

        self.disassemble_cases(program, addresses_to_dissemble)

        self.fixup_function(program, instruction, addresses_to_dissemble, monitor)

    def process_lookup_switch(self, program, reader, instruction, monitor):
        alignment_pad = Register("alignmentPad")
        alignment = int(instruction.value(alignment_pad, False))

        if len(instruction.op_objects(0)) == 0:
            Msg.info(self, "Skipping lookupswitch instruction - missing operand reference for default case.")
            return

        op_objects = instruction.op_objects(0)
        default_offset = (Scalar(op_objects[0])).unsigned_value()
        number_of_cases = (Scalar(op_objects[1])).unsigned_value()

        addresses_to_disassemble = []

        # Handle the default case
        address_to_dissemble = instruction.min_address().add(default_offset)
        addresses_to_dissemble.append(address_to_dissemble)
        self.add_label_and_reference(program, instruction, address_to_dissemble, "default")

        base = instruction.memory().min_address().offset()
        index = instruction.min_address().offset()
        index -= base
        index += (1 + alignment + 4)  # lookupswitch opcode + alignment + size of default

        reader.set_pointer_index(index)

        for i in range(number_of_cases):
            try:
                match = int(reader.read_next_int())
                offset = int(reader.read_next_int())
                address_to_dissemble = instruction.min_address().add(offset)
                addresses_to_dissemble.append(address_to_dissemble)
                label = "case_{}_(0x{})".format(match, hex(match))
                self.add_label_and_reference(program, instruction, address_to_disassemble, label)
            except IOException as e:
                Msg.error(self, str(e))

        self.disassemble_cases(program, addresses_to_dissemble)

        self.fixup_function(program, instruction, addresses_to_dissemble, monitor)

    def disassemble_cases(self, program, addresses):
        for addr in addresses:
            d_command = DisassembleCommand(addr, None, True)
            d_command.apply_to(program)

    def add_label_and_reference(self, program, switch_instruction, target, label):
        reference_manager = program.reference_manager()
        reference_manager.add_memory_reference(switch_instruction.min_address(), target,
                                                 RefType.COMPUTED_JUMP, SourceType.ANALYSIS, CodeUnit.MNEMONIC)

        # Put switch table cases into namespace for the switch
        space = None

        try:
            space = program.symbol_table().create_name_space(None, label, SourceType.ANALYSIS)
        except DuplicateNameException as e:
            pass  # Ignore exceptions for now
        except InvalidInputException as e1:
            pass  # Just go with default space

        if target not in [addr.min_address() for addr in program.listing().instructions(program)]:
            try:
                program.symbol_table().create_label(target, label, space, SourceType.ANALYSIS)
            except InvalidInputException as e2:
                Msg.error(self, str(e2))

    def fixup_function(self, program, instruction, additions, monitor):
        func = program.function_manager().get_function_containing(instruction.min_address())
        new_body = AddressSet(func.body())

        for addr in additions:
            new_body.add(addr)

        try:
            func.set_body(new_body)
        except OverlappingFunctionException as e:
            pass  # TODO Auto-generated catch block
            e.printStackTrace()

        try:
            CreateFunctionCmd.fixup_function_body(program, func, monitor)
        except CancelledException as e:
            pass  # TODO Auto-generated catch block
            e.printStackTrace()
