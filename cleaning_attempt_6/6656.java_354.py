class InstructionSequenceTreePanelBuilder:
    def __init__(self, type):
        self.type = type
        # Initialize other attributes here if needed

    def build_tree_panel(self):
        panel = JPanel()
        panel.setBorder(EmptyBorder(3, 3, 3, 3))
        root_node = FunctionBitPatternsGTreeRootNode()
        default_empty_tree = GTree(root_node)
        panel.add(default_empty_tree, BorderLayout.CENTER)
        return panel

    def build_main_panel(self):
        main_panel = JPanel()
        main_panel.setLayout(BorderLayout())
        tree_panel = self.build_tree_panel()
        count_panel = self.build_count_panel()
        main_panel.add(count_panel, BorderLayout.NORTH)
        main_panel.add(tree_panel, BorderLayout.CENTER)
        button_panel = self.get_button_panel()
        main_panel.add(button_panel, BorderLayout.SOUTH)
        return main_panel

    def add_percentage_filter_buttons(self):
        apply_percentage_filter_button = JButton(APPLY_PERCENTAGE_FILTER_BUTTON_TEXT)
        apply_percentage_filter_button.addActionListener(
            ActionListener(lambda event: self.apply_percentage_filter_action())
        )
        button_panel = self.get_button_panel()
        button_panel.add(apply_percentage_filter_button)

        clear_percentage_filter_button = JButton(CLEAR_PERCENTAGE_FILTER_BUTTON_TEXT)
        clear_percentage_filter_button.addActionListener(
            ActionListener(lambda event: self.clear_percentage_filter_action())
        )
        button_panel.add(clear_percentage_filter_button)

    def build_count_panel(self):
        count_panel = JPanel()
        pair_layout = PairLayout()
        count_panel.setLayout(pair_layout)
        label = GDLabel(COUNT_FIELD_LABEL)
        count_panel.add(label)
        field = JTextField(25, False)
        count_panel.add(field)
        return count_panel

    def update_count_field(self, num_seqs):
        field = self.count_field
        if not isinstance(num_seqs, int) or num_seqs < 0:
            raise ValueError("Number of sequences must be a non-negative integer")
        field.setText(str(num_seqs))

    def update_tree_panel(self):
        tree_panel.remove_all()
        reg_filter = self.get_context_register_filter()
        inst_seqs = InstructionSequence.get_inst_seqs(
            fs_reader, self.type, reg_filter
        )
        gtree = FunctionBitPatternsGTree.create_tree(inst_seqs, self.type, percentage_filter)
        gtree.set_root_visible(False)
        gtree.selection_model().set_selection_mode(TreeSelectionModel.SINGLE_TREE_SELECTION)
        tree_panel.add(gtree)
        tree_panel.update_ui()
        self.update_count_field(len(inst_seqs))

    def set_fs_reader_and_update_extent(self, fs_reader):
        self.fs_reader = fs_reader
        update_extent_and_clear_filter(fs_reader.get_context_register_extent())
        self.update_tree_panel()

    def is_tree_empty(self):
        if gtree is None:
            return True
        return gtree.total_num() == 0

    def apply_filter_action(self):
        self.update_tree_panel()

    def clear_filter_action(self):
        update_extent_and_clear_filter(fs_reader.get_context_register_extent())
        self.update_tree_panel()

    def enable_percentage_filter_buttons(self, enable):
        if apply_percentage_filter_button is not None:
            apply_percentage_filter_button.set_enabled(enable)
        if clear_percentage_filter_button is not None:
            clear_percentage_filter_button.set_enabled(enable)

    def get_selection_path(self):
        if gtree is None:
            return None
        paths = gtree.get_selection_paths()
        if paths is None or len(paths) == 0:
            return None
        return paths[0]

    def get_g_tree(self):
        return self.gtree

class FunctionBitPatternsGTreeRootNode:
    pass

class GTree:
    @staticmethod
    def create_tree(inst_seqs, type, percentage_filter):
        # Implement this method to create the tree based on inst_seqs and other parameters.
        pass

# Initialize attributes here if needed
