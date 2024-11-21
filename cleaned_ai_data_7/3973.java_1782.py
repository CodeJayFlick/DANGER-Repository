class InsertBytesWidget:
    def __init__(self, program, dialog):
        self.dialog = dialog
        self.program = program
        self.disassembler = PseudoDisassembler(program)
        super().__init__("Edit Bytes", False, True, True, False)

    def applyCallback(self):
        self.disassemble()

    def loadBytes(self, bytes):
        import threading

        thread = threading.Thread(target=lambda: (self.input_bytes_ta.setText(bytes), self.apply_button.doClick()))
        thread.start()

    def getInputString(self):
        return self.input_bytes_ta.getText()

    def setInputString(self, input_string):
        self.input_bytes_ta.setText(input_string)

    def dialogShown(self):
        self.populateDialog()
        self.to_front()

    def createWorkPanel(self):
        panel = JPanel()
        panel.setMinimumSize((500, 300))

        self.input_bytes_ta = HintTextAreaIS("<input hex or binary data; full bytes only>")
        scrollpane = JScrollPane(self.input_bytes_ta)
        self.input_bytes_ta.addKeyListener(self)

        selection_mode_widget = SelectionModeWidget("Input Mode", self)
        endian_flip_widget = EndianFlipWidget("Endianness", self)
        msg_panel = MessagePanel()

        south_panel = JPanel()
        south_panel.setLayout(BorderLayout())
        south_panel.add(selection_mode_widget, BorderLayout.WEST)
        south_panel.add(endian_flip_widget, BorderLayout.CENTER)
        south_panel.add(msg_panel, BorderLayout.SOUTH)

        panel.setLayout(BorderLayout())
        panel.add(scrollpane, BorderLayout.CENTER)
        panel.add(south_panel, BorderLayout.SOUTH)

        return panel

    def populateDialog(self):
        self.msg_panel.clear()

        input_string = self.input_bytes_ta.getText()
        instructions = self.dialog.get_search_data().get_instructions()
        combined_string = self.dialog.get_search_data().get_combined_string()
        for instruction in instructions:
            instr_len = len(instruction.get_mask_container().to_binary_string())
            instr_str = combined_string[:instr_len]
            combined_string = combined_string[instr_len:]
            instr_str = InstructionSearchUtils.add_space_on_byte_boundary(instr_str, InputMode.BINARY)
            self.input_bytes_ta.setText(self.input_bytes_ta.getText() + "\n" + instr_str)

        self.selection_mode_widget.set_input_mode(InputMode.BINARY)
        self.input_bytes_ta.setSelectionStart(0)
        self.input_bytes_ta.setSelectionEnd(len(input_string))

    def disassemble(self):
        if not hasattr(self, "dialog"):
            return

        self.msg_panel.clear()

        input_string = self.input_bytes_ta.getText()
        all_bytes = InstructionSearchUtils.to_byte_array(input_string)

        while len(all_bytes) > 0:
            try:
                bytearray = [bytearray(1)[0] for _ in range(len(all_bytes))]
                all_bytes = list(bytearray)
                instruction = self.disassembler.disassemble(self.program.get_min_address(), InstructionSearchUtils.to_primitive(bytearray))
                metadata = create_instruction_metadata(instruction)
                operands = create_operand_metadata(instruction)

                instructions.append(metadata)
                all_bytes = all_bytes[:len(instruction)]

            except (MemoryAccessException, InsufficientBytesException):
                self.msg_panel.setMessageText("Input invalid: unknown disassembly error.", Color.RED)
                return

        self.dialog.get_search_data().set_instructions(instructions)

    def create_operand_metadata(self, instruction):
        operands = []

        for i in range(len(instruction)):
            operand_md = OperandMetadata()
            operand_md.set_op_type(instruction[i])
            operand_md.setText_rep(instruction.getDefault_operand_representation(i))

            mask_container = MaskContainer(mask=instruction.get_prototype().get_operand_value_mask(i), value=InstructionSearchUtils.byte_array_and(mask, instruction.getBytes()))
            operand_md.set_mask_container(mask_container)

            operands.append(operand_md)
        return operands

    def create_instruction_metadata(self, instruction):
        metadata = InstructionMetadata()
        mask_container = MaskContainer(mask=instruction.get_prototype().get_instruction_mask(), value=InstructionSearchUtils.byte_array_and(mask, instruction.getBytes()))
        metadata.set_is_instruction(True)
        metadata.setText_rep(instruction.getMnemonic_string())

        return metadata

    def validate_input(self):
        text = self.input_bytes_ta.getText()
        if not text:
            self.error_msg = "No input specified!"
            return False
        if self.selection_mode_widget.get_input_mode() == InputMode.BINARY:
            try:
                InstructionSearchUtils.get_group_sizes(text, InputMode.BINARY)
            except Exception as e:
                self.input_bytes_ta.setError()
                self.error_msg = "Groups must contain full bytes (no individual bits or nibbles!)."
                return False
        elif self.selection_mode_widget.get_input_mode() == InputMode.HEX:
            try:
                InstructionSearchUtils.get_group_sizes(text, InputMode.HEX)
            except Exception as e:
                self.input_bytes_ta.setError()
                self.error_msg = "Hex mode selected. Please adjust your input to be valid"
                return False
        if not InstructionSearchUtils.is_binary(text):
            self.input_bytes_ta.setError()
            self.error_msg = "Binary mode selected. Please adjust your input to be valid"
            return False
        elif not InstructionSearchUtils.is_full_hex_byte(text):
            self.input_bytes_ta.setError()
            self.error_msg = "Hex mode selected. Please adjust your input to be valid"
            return False

    def keyTyped(self, e):
        pass

    def keyPressed(self, e):
        pass

    def keyReleased(self, e):
        self.validate_input()

    @property
    def selection_mode_widget(self):
        return self.selection_mode_widget
