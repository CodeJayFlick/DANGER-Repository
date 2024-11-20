class EditReferenceDialog:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Edit Reference", True)
        self.add_work_panel(self.build_main_panel())
        self.add_apply_button()
        self.add_cancel_button()

        self.default_button(apply_button)

    def dispose(self):
        self.close()
        self.cleanup()

    @property
    def current_code_unit(self):
        return self.instr_panel.current_code_unit

    def cleanup(self):
        self.mem_ref_panel.cleanup()
        self.ext_ref_panel.cleanup()
        self.stack_ref_panel.cleanup()
        self.reg_ref_panel.cleanup()

    def build_main_panel(self):
        top_panel = JPanel(BoxLayout.Y_AXIS)
        instr_panel = InstructionPanel(5, 5, 5, 5, None, self.plugin, InstructionPanelListener())
        top_panel.add(instr_panel)

        ref_type_panel = JPanel()
        ref_type_panel.setBorder(BorderFactory.createTitledBorder("Type of Reference", BorderFactory.createEtchedBorder()))
        mem_ref_choice = JRadioButton("Memory")
        ext_ref_choice = JRadioButton("External")
        stack_ref_choice = JRadioButton("Stack")
        reg_ref_choice = JRadioButton("Register")

        for choice in [mem_ref_choice, ext_ref_choice, stack_ref_choice, reg_ref_choice]:
            choice.addChangeListener(ChangeAdapter(self.ref_choice_activated))

        button_group = ButtonGroup()
        button_group.add(mem_ref_choice)
        button_group.add(ext_ref_choice)
        button_group.add(stack_ref_choice)
        button_group.add(reg_ref_choice)

        for panel in [mem_ref_panel, ext_ref_panel, stack_ref_panel, reg_ref_panel]:
            ref_type_panel.add(panel)

        bottom_panel = JPanel()
        bottom_panel.setLayout(CardLayout())
        bottom_panel.setPreferredSize((450, 190))

        return top_panel

    def set_add_op_index(self, op_index, sub_index):
        code_unit = self.instr_panel.current_code_unit
        program = code_unit.get_program()

        in_function = (program.function_manager().get_function_containing(code_unit.min_address) is not None)
        refs = [ref for ref in program.reference_manager().references_from(code_unit.min_address, op_index)]

        address = refs[0].to_address if len(refs) > 0 else None

        self.mem_ref_panel.initialize(code_unit, op_index, sub_index)

        mem_ref_choice.setEnabled(True)
        ext_ref_choice.setEnabled(ext_ref_panel.is_valid_external_ref())
        stack_ref_choice.setEnabled(in_function and stack_ref_panel.is_valid_stack_ref())
        reg_ref_choice.setEnabled(in_function and reg_ref_panel.is_valid_register_ref())

    def ref_choice_activated(self, event):
        if isinstance(event.getSource(), JRadioButton):
            choice = event.getSource()
            self.active_ref_panel = {
                "Memory": mem_ref_panel,
                "External": ext_ref_panel,
                "Stack": stack_ref_panel,
                "Register": reg_ref_panel
            }[choice.get_text()]

            bottom_layout.show(bottom_panel, self.active_ref_panel.name)
            self.active_ref_panel.request_focus()

    def init_dialog(self, code_unit, op_index, sub_index, reference):
        initializing = True

        self.instr_panel.set_code_unit_location(code_unit, op_index, sub_index, reference is not None)

        if reference:
            self.configure_edit_reference(code_unit, reference)
        else:
            self.configure_add_reference(op_index, sub_index)

        initializing = False
        self.active_ref_panel.request_focus()

    def configure_add_reference(self, op_index, sub_index):
        self.set_title("Add Reference")
        self.set_help_location(ADD_HELP)

        apply_button.setText("Add")

        self.set_add_op_index(op_index, sub_index)

    def configure_edit_reference(self, code_unit, reference):
        self.set_title("Edit Reference")
        self.set_help_location(EDIT_HELP)

        apply_button.setText("Update")

        to_address = reference.to_address
        if to_address.is_register_address() or code_unit.get_program().get_register(to_address) is not None:
            reg_ref_panel.initialize(code_unit, reference)
            reg_ref_choice.setSelected(True)
            reg_ref_choice.setEnabled(True)
            if to_address.is_memory_address():
                mem_ref_panel.initialize(code_unit, reference)
                mem_ref_choice.setEnabled(True)

        elif to_address.is_stack_address():
            stack_ref_panel.initialize(code_unit, reference)
            stack_ref_choice.setSelected(True)
            stack_ref_choice.setEnabled(True)

        elif to_address.is_external_address():
            ext_ref_panel.initialize(code_unit, reference)
            ext_ref_choice.setSelected(True)
            ext_ref_choice.setEnabled(True)

    def apply_callback(self):
        if self.active_ref_panel.apply_reference():
            self.close()
            self.cleanup()

    def cancel_callback(self):
        self.close()
        self.cleanup()

    def read_data_state(self, save_state):
        element = save_state.get_xml_element("MemoryReferencePanelState")
        if element is not None:
            mem_ref_panel.read_xml_data_state(element)

    def write_data_state(self, save_state):
        element = Element("MemoryReferencePanelState")
        mem_ref_panel.write_xml_data_state(element)
        save_state.put_xml_element("MemoryReferencePanelState", element)
