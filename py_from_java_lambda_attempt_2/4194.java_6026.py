Here is a translation of the Java code into Python:

```Python
class InstructionPanel:
    def __init__(self, top_pad=0, left_pad=0, bottom_pad=0, right_pad=0,
                 go_home_action=None, plugin=None, listener=None):
        self.drop_supported = False if listener is None else listener.drop_supported()
        self.go_home_action = go_home_action
        self.symbol_inspector = plugin.get_symbol_inspector() if plugin else None
        self.cu_format = plugin.get_code_unit_format() if plugin else None
        self.listener = listener

    def get_current_code_unit(self):
        return self.current_code_unit

    def set_code_unit_location(self, cu, op_index=-1, sub_index=0, locked=False):
        if cu:
            self.locked = locked
            self.address_label.set_text(cu.get_min_address().to_string())
            memory = cu.get_program().get_memory()
            self.cu_format.add_change_listener(self)
        else:
            self.cu_format.remove_change_listener(self)
            self.locked = False
            self.address_label.set_text("")
            memory = None

        self.current_code_unit = cu
        self.active_index = ReferenceManager.MNEMONIC - 1  # force update_labels to work
        self.update_labels(op_index, sub_index)

    def set_selected_op_index(self, index=-1, sub_index=0):
        self.update_labels(index, sub_index)

    def get_selected_op_index(self):
        return self.active_index

    def get_selected_sub_op_index(self):
        return self.active_sub_index

    def create(self, top_pad=0, left_pad=0, bottom_pad=0, right_pad=0):
        layout = BorderLayout()
        self.setLayout(layout)

        border = TitledBorder(EmptyBorder(), "Source")
        self.setBorder(border)

        self.address_label = GDLabel("FFFFFFFF")  # use a default
        font = self.address_label.get_font()
        mono_font = Font(font.get_name(), font.get_style(), font.get_size())
        self.address_label.set_font(mono_font)
        self.address_label.set_name("addressLabel")

        mnemonic_label = GDLabel("movl")
        mnemonic_label.set_font(mono_font)
        mnemonic_label.set_name("mnemonicLabel")
        mnemonic_label.add_mouse_listener(self.mouse_listener)

        operand_labels = [GDLabel("%ebp, ") for _ in range(Program.MAX_OPERANDS)]
        for i, label in enumerate(operand_labels):
            label.set_font(mono_font)
            label.set_name(f"operandLabels[{i}]")
            label.add_mouse_listener(self.mouse_listener)

        inner_panel = JPanel()
        box_layout = BoxLayout(inner_panel, BoxLayout.X_AXIS)
        inner_panel.setLayout(box_layout)

        if self.go_home_action:
            action = KeyBindingUtils.adapt_docking_action_to_non_context_action(
                self.go_home_action
            )
            home_button = JButton(action)
            home_button.set_text(None)
            home_button.set_margin(Insets(0, 0, 0, 0))
            home_button.set_focusable(False)
            inner_panel.add(Box.create_horizontal_strut(5))
            inner_panel.add(home_button)

        inner_panel.add(Box.create_horizontal_strut(5))
        inner_panel.add(self.address_label)
        inner_panel.add(Box.create_horizontal_strut(20))
        inner_panel.add(mnemonic_label)
        for label in operand_labels:
            inner_panel.add(label)
            inner_panel.add(Box.create_horizontal_strut(5))

        self.add(inner_panel, BorderLayout.CENTER)

    def update_labels(self, index=-1, sub_index=0):
        prev_index = self.active_index
        self.active_index = index
        self.active_sub_index = sub_index

        for label in operand_labels:
            label.set_text("")
            label.setBorder(EmptyBorder())
            label.setBackground(get_parent().get_background())

        if self.current_code_unit:
            n_operands = self.current_code_unit.get_num_operands()
            for i, op_rep in enumerate([self.cu_format.get_operand_representation_string(
                self.current_code_unit, j
            ) for j in range(n_operands)]):
                if i < n_operands - 1:
                    op_rep += ","
                set_operand_attributes(i, op_rep)
        else:
            mnemonic_label.set_text("")
            mnemonic_label.setBorder(EmptyBorder())
            mnemonic_label.setBackground(get_parent().get_background())

    def get_operand_color(self, op_index=-1):
        program = self.current_code_unit.get_program()

        ref = None
        if op_index < len(operand_labels) - 1:
            ref = self.current_code_unit.get_primary_reference(op_index)
        else:
            ref_addr = self.current_code_unit.get_address(op_index)

        if not ref_addr or not program.get_memory().contains(ref_addr):
            return NOT_IN_MEMORY_COLOR

        symbol_table = program.get_symbol_table()
        sym = symbol_table.get_symbol(ref) if ref else None
        color = DEFAULT_FG_COLOR
        if sym:
            self.symbol_inspector.set_program(program)
            color = self.symbol_inspector.get_color(sym)

        return color

    def set_operand_attributes(self, op_index=-1, operand_text=""):
        label = operand_labels[op_index]
        label.set_text(operand_text)
        label.setForeground(get_operand_color(op_index))

        if self.active_index == op_index:
            label.setBorder(ETCHED_BORDER)
            label.setBackground(HIGHLIGHT_COLOR)
            label.setOpaque(True)
        else:
            label.setBackground(get_parent().get_background())
            label.setBorder(EmptyBorder())
            label.setOpaque(False)

    def set_mnemonic_attributes(self, mnemonic_text=""):
        self.mnemonic_label.set_text(mnemonic_text)
        self.mnemonic_label.setForeground(DEFAULT_FG_COLOR)

        if self.active_index == ReferenceManager.MNEMONIC:
            self.mnemonic_label.setBackground(HIGHLIGHT_COLOR)
            self.mnemonic_label.setBorder(ETCHED_BORDER)
            self.mnemonic_label.setOpaque(True)
        else:
            self.mnemonic_label.setBackground(get_parent().get_background())
            self.mnemonic_label.setBorder(EmptyBorder())
            self.mnemonic_label.setOpaque(False)

    def get_label_index(self, label):
        for i in range(len(operand_labels)):
            if operand_labels[i] == label:
                return i
        return ReferenceManager.MNEMONIC

class LabelMouseListener(MouseAdapter):
    def mouse_entered(self, e):
        if not self.locked:
            label = e.get_source()
            label.setCursor(Cursor.HAND_CURSOR)

    def mouse_exited(self, e):
        label = e.get_source()
        label.setCursor(Cursor.getDefaultCursor())

    def mouse_pressed(self, e):
        if not self.locked:
            label = e.get_source()
            update_labels(get_label_index(label), -1)
```

Please note that this is a direct translation of the Java code into Python. It may require some adjustments to work correctly in your specific environment.