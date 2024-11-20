Here is the translation of the given Java code into Python:

```Python
class ObjectiveC2MessageAnalyzer:
    NAME = "Objective-C 2 Message"
    DESCRIPTION = "An analyzer for extracting Objective-C 2.0 message information."

    def __init__(self):
        super().__init__(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER)
        self.setPrototype()
        # The Objective-C 2.0 analyzer should always run after the class analyzer.
        # It knows the deal!
        self.setPriority(AnalysisPriority.FORMAT_ANALYSIS.after())

    def added(self, program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog) -> bool:
        iterator = set.getAddresses(True)
        while iterator.hasNext():
            address = iterator.next()
            function = program.getListing().getFunctionAt(address)

            try:
                self.inspect_function(program, function, monitor)
            except Exception as e:
                # ignore
                pass

        return True

    def can_analyze(self, program: Program) -> bool:
        return ObjectiveC2Constants.is_objective_c_2(program)

    def inspect_function(self, program: Program, function: Function, monitor: TaskMonitor):
        if function is None:
            return

        instruction_iterator = program.getListing().getInstructions(function.getBody(), True)
        while instruction_iterator.hasNext():
            instruction = instruction_iterator.next()

            if self.is_calling_objc_msg_send(instruction):
                eol_comment = instruction.getComment(CodeUnit.EOL_COMMENT)

                if eol_comment is not None:  # if a comment already exists, ignore...
                    continue

                self.markup_instruction(program, instruction, monitor)
        return True

    def is_calling_objc_msg_send(self, instruction: Instruction) -> bool:
        if instruction.getNumOperands() != 1:
            return False
        reference = instruction.getPrimaryReference(0)

        if reference is None or not (reference.getReferenceType().isCall() and reference.getReferenceType().isJump()):
            return False

        symbol_table = instruction.getProgram().getSymbolTable()
        symbol = symbol_table.getPrimarySymbol(reference.getToAddress())

        return self.is_objc_name_match(symbol)

    def is_objc_name_match(self, symbol: Symbol) -> bool:
        name = symbol.getName()

        if name.startswith(ObjectiveC1Constants.OBJC_MSG_SEND):
            return True
        elif name == ObjectiveC1Constants.READ_UNIX2003:
            return True

        return False

    def markup_instruction(self, program: Program, instruction: Instruction, monitor: TaskMonitor):
        from_address = instruction.getMinAddress()
        function = program.getListing().getFunctionContaining(from_address)

        if function is None:
            return

        current_class = None
        current_method = None

        iter = program.getListing().getInstructions(from_address, False)
        while iter.hasNext():
            if monitor.isCancelled():
                break  # don't look outside of the function

            instruction_before = iter.next()

            if not function.getBody().contains(instruction_before.getMinAddress()):
                break  # don't look outside of the function

            register_modified = False
            if self.is_register_modified(instruction_before, "r0"):
                current_class = None
                register_modified = True
            elif self.is_register_modified(instruction_before, "r1"):
                current_method = None
                register_modified = True

            if not self.is_valid_instruction(instruction_before):
                if register_modified:
                    break  # don't look outside of the function
                continue

            first_operand_objects = instruction_before.getOpObjects(0)
            if len(first_operand_objects) != 1 or not isinstance(first_operand_objects[0], Register):
                continue

            register = first_operand_objects[0]

            if register.getName() == "r0" or register.getName() == "r1":
                to_address = instruction_before.getPrimaryReference(0).getToAddress()

                block = program.getMemory().getBlock(to_address)
                if block is None:
                    return

                if register.getName() == "r0":  # class
                    current_class = self.get_class_name(program, to_address)
                elif register.getName() == "r1":  # method
                    current_method = self.get_method_name(program, to_address)

                instruction.setComment(CodeUnit.EOL_COMMENT, "[" + str(current_class) + " " + str(current_method) + "]")
                break

    def is_register_modified(self, instruction: Instruction, register_name: str) -> bool:
        destination_operand_objects = instruction.getOpObjects(0)
        if len(destination_operand_objects) != 1 or not isinstance(destination_operand_objects[0], Register):
            return False
        register = destination_operand_objects[0]

        return register.getName() == register_name

    def get_class_name(self, program: Program, address: Address) -> str:
        try:
            class_pointer_value = program.getMemory().getInt(address)
            class_pointer_address = address.getNewAddress(class_pointer_value)

            if not self.is_objc_class_ref_block(program, class_pointer_address):
                return None

            data = program.getListing().getDefinedDataAt(class_pointer_address)
            class_address = (data.getValue())

            if not self.is_objc_data_block(program, class_address):
                return None

            data = program.getListing().getDefinedDataAt(class_address)
            classNamePointerData = data.getComponent(4)

            address = (classNamePointerData.getValue())
            if not self.is_c_string_block(program, address):
                return None
            data = program.getListing().getDefinedDataAt(address)
            return str(data.getValue())

        except Exception as e:
            # ignore
            pass

    def get_method_name(self, program: Program, address: Address) -> str:
        try:
            method_pointer_value = program.getMemory().getInt(address)
            method_pointer_address = address.getNewAddress(method_pointer_value)

            if not self.is_objc_selector_ref_block(program, method_pointer_address):
                return None

            data = program.getListing().getDefinedDataAt(method_pointer_address)
            method_address = (data.getValue())

            if not self.is_c_string_block(program, method_address):
                return None
            data = program.getListing().getDefinedDataAt(method_address)
            return str(data.getValue())
        except Exception as e:
            # ignore
            pass

    def is_valid_instruction(self, instruction: Instruction) -> bool:
        if instruction.getNumOperands() != 2:
            return False
        is_mov = instruction.getMnemonicString() == "MOV"  # intel 
        is_lwz = instruction.getMnemonicString() == "lwz"  # powerpc
        is_ldr = instruction.getMnemonicString() == "ldr"  # arm

        return is_move or is_lwz or is_ldr

    def is_c_string_block(self, program: Program, address: Address) -> bool:
        block = program.getMemory().getBlock(address)
        if block is None:
            return False
        return block.getName() == SectionNames.TEXT_CSTRING

    def is_objc_selector_ref_block(self, program: Program, address: Address) -> bool:
        block = program.getMemory().getBlock(address)
        if block is None:
            return False
        return block.getName() == ObjectiveC2Constants.OBJC2_SELECTOR_REFS

    def is_objc_class_ref_block(self, program: Program, address: Address) -> bool:
        block = program.getMemory().getBlock(address)
        if block is None:
            return False
        return block.getName() == ObjectiveC2Constants.OBJC2_CLASS_REFS

    def is_objc_const_block(self, program: Program, address: Address) -> bool:
        block = program.getMemory().getBlock(address)
        if block is None:
            return False
        return block.getName() == ObjectiveC2Constants.OBJC2_CONST

    def is_objc_data_block(self, program: Program, address: Address) -> bool:
        block = program.getMemory().getBlock(address)
        if block is None:
            return False
        return block.getName() == ObjectiveC2Constants.OBJC2_DATA