Here is the translation of the Java code into Python:

```Python
class EditExternalReferencePanel:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("EXT")
        self.build_panel()

    def build_panel(self):
        top_panel = JPanel(5, 10, 160)
        top_panel.setBorder(
            CompoundBorder(TitledBorder("External Program"), EmptyBorder(0, 5, 5, 5))
        )
        
        label1 = GLabel("Name:", SwingConstants.RIGHT)
        self.ext_lib_name = GhidraComboBox()
        self.ext_lib_name.setEditable(True)
        self.ext_lib_name.add_document_listener(self)
        top_panel.add(label1)
        top_panel.add(self.ext_lib_name)

        ext_lib_path = JTextField()
        ext_lib_path.setBackground(get_background())
        ext_lib_path.setEditable(False)
        ext_lib_path.set_focusable(False)

        clear_button = JButton("Clear")
        clear_button.setToolTipText("Remove Link to External Program")
        clear_button.addActionListener(self)
        
        edit_button = JButton("Edit")
        edit_button.setToolTipText("Edit Link to External Program")
        edit_button.addActionListener(self)

        path_panel = JPanel(BorderLayout())
        path_panel.add(ext_lib_path, BorderLayout.CENTER)
        button_panel = JPanel(FlowLayout.LEFT, 0, 0)
        button_panel.add(clear_button)
        button_panel.add(edit_button)
        path_panel.add(button_panel, BorderLayout.EAST)

        top_panel.add(GLabel("Path:", SwingConstants.RIGHT))
        top_panel.add(path_panel)

        bottom_panel = JPanel(PairLayout(10, 10, 160))
        bottom_panel.setBorder(
            CompoundBorder(TitledBorder("External Reference Data"), EmptyBorder(0, 5, 5, 5))
        )
        
        label2 = GLabel("Label:", SwingConstants.RIGHT)
        self.ext_label = JTextField()
        bottom_panel.add(label2)
        bottom_panel.add(self.ext_label)

        label3 = GLabel("Address:", SwingConstants.RIGHT)
        self.ext_addr = AddressInput()
        bottom_panel.add(label3)
        bottom_panel.add(self.ext_addr)

        layout = VerticalLayout(5)
        add(top_panel, layout)
        add(bottom_panel, layout)

    def ext_prog_name_changed(self):
        has_text = len(str(self.ext_lib_name.get_text()).strip()) != 0
        self.clear_button.set_enabled(has_text)
        self.edit_button.set_enabled(has_text)
        self.ext_lib_path.set_text(None)

    def populate_external_names(self):
        names = from_code_unit.get_program().get_external_manager().get_external_library_names()
        self.ext_lib_name.clear_model()
        self.ext_lib_name.add_item(Library.UNKNOWN)
        sorted(names)
        for i in range(len(names)):
            if Library.UNKNOWN == name:
                continue
            self.ext_lib_name.add_item(name)

    def update_ext_lib_path(self):
        name = str(self.ext_lib_name.get_text()).strip()
        path = None
        if len(name) != 0:
            name = name.strip()
            path = from_code_unit.get_program().get_external_manager().get_external_library_path(name)
        self.ext_lib_path.set_text(path)

    def popup_program_chooser(self):
        data_tree_dialog = DataTreeDialog(self.parent, "Choose External Program", DataTreeDialog.OPEN)
        final_data_tree_dialog = data_tree_dialog
        data_tree_dialog.add_ok_action_listener(self)
        plugin.get_tool().show_dialog(data_tree_dialog)
        if df == None:
            return
        path_name = str(df.get_pathname())
        if path_name == from_code_unit.get_program().get_domain_file().get_pathname():
            dialog.set_status_text("Selected program is the same as current program")
            return
        dialog.close()
        self.ext_lib_path.set_text(str(df.get_pathname()))

    def initialize(self, code_unit, reference):
        self.isValid_state = False
        this.from_code_unit = code_unit

        program = from_code_unit.get_program()

        to_addr = reference.get_to_address()
        if not to_addr.is_external_address():
            raise ValueError("Expected external reference")
        this.edit_ref = ExternalReference(reference)
        ext_loc = edit_ref.get_external_location()

        self.populate_external_names()
        name = str(ext_loc.get_library_name())
        self.ext_lib_name.set_selected_item(name)
        self.ext_prog_name_changed()

        update_ext_lib_path()

        label = str(ext_loc.get_label())
        if len(label) != 0:
            label = label.strip()
        self.ext_label.set_text(label)

        addr = ext_loc.get_address()
        if addr == None:
            self.ext_addr.clear()
        else:
            self.ext_addr.set_address(addr)
        self.ext_lib_name.request_focus()

        self.isValid_state = True

    def set_op_index(self, op_index):
        if edit_ref != None:
            raise ValueError("setOpIndex only permitted for ADD case")
        
        self.isValid_state = False
        this.op_index = op_index
        
        return True

    def apply_reference(self):
        if not self.isValid_state:
            raise ValueError()
        
        name = str(self.ext_lib_name.get_text())
        if len(name) == 0 or len(str(name).strip()) == 0:
            show_input_err("An external program 'Name' must be specified.")
            return False
        name = str(name).strip()

        library_program_pathname = str(self.ext_lib_path.get_text())

        addr = self.ext_addr.get_address()
        label = str(self.ext_label.get_text())
        
        if edit_ref != None:
            plugin.update_reference(edit_ref, from_code_unit, name, library_program_pathname, addr, label)
        else:
            return plugin.add_reference(from_code_unit, op_index, name, library_program_pathname, addr, label)

    def cleanup(self):
        self.isValid_state = False
        this.from_code_unit = None
        edit_ref = None

    def is_valid_context(self):
        return self.isValid_state