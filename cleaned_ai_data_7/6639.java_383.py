class ByteSequencePanelBuilder:
    def __init__(self, plugin: 'FunctionBitPatternsExplorerPlugin', type: 'PatternType'):
        self.plugin = plugin
        self.type = type

    @property
    def last_selected_rows(self) -> list['ByteSequenceRowObject']:
        return self.byte_seq_table.get_last_selected_objects()

    def apply_filter_action(self):
        self.update_table()

    def clear_filter_action(self):
        self.update_extent_and_clear_filter(self.fs_reader.get_context_register_extent())
        self.update_table()

    @property
    def is_length_filtered(self) -> bool:
        return self.length_filter is not None

    @property
    def length_filter(self) -> 'ByteSequenceLengthFilter':
        return self.length_filter

    @property
    def pattern_type(self) -> 'PatternType':
        return self.type

    def build_main_panel(self):
        main_panel = JPanel()
        num_seqs_panel = JPanel()
        pair_layout = PairLayout()
        num_seqs_panel.setLayout(pair_layout)
        num_seqs_label = GLabel(NUM_SEQS_LABEL_TEXT)
        num_seqs_field = JTextField(25, editable=False)
        num_seqs_panel.add(num_seqs_label)
        num_seqs_panel.add(num_seqs_field)

        main_panel.add(num_seqs_panel, BorderLayout.NORTH)

        button_panel = self.get_button_panel()
        main_panel.add(button_panel, BorderLayout.SOUTH)

        byte_seq_table = DisassembledByteSequenceTableModel(self.plugin, self.row_objects)
        filter_table = GFilterTable(byte_seq_table)
        main_panel.add(filter_table, BorderLayout.CENTER, TABLE_INDEX)

        self.add_length_filter_and_analysis_buttons()

    def update_table(self):
        main_panel.remove(TABLE_INDEX)
        filter_table.dispose()
        
        row_objects = ByteSequenceRowObject.get_filtered_row_objects(
            self.fs_reader.get_f_info_list(), 
            self.type,
            self.context_register_filter(),
            self.length_filter
        )
        byte_seq_table = DisassembledByteSequenceTableModel(self.plugin, row_objects)
        filter_table = GFilterTable(byte_seq_table)

        total_num_seqs = 0
        for row in row_objects:
            total_num_seqs += row.get_num_occurrences()
        
        num_seqs_field.setText(str(total_num_seqs))

        main_panel.add(filter_table, BorderLayout.CENTER, TABLE_INDEX)
        main_panel.update_ui()

    def set_fs_reader(self, fs_reader: 'FileBitPatternInfoReader'):
        self.fs_reader = fs_reader
        self.update_extent_and_clear_filter(fs_reader.get_context_register_extent())
        self.length_filter = None
        self.update_table()

    def add_length_filter_and_analysis_buttons(self):
        apply_button_text = APPLY_LENGTH_FILTER_BUTTON_TEXT
        clear_button_text = CLEAR_LENGTH_FILTER_BUTTON_TEXT

        apply_button = JButton(apply_button_text)
        button_panel.add(apply_button)

        apply_button.addActionListener(lambda e: 
            filter_creator = ByteSequenceLengthFilterInputDialog(
                BYTE_SEQUENCE_LENGTH_FILTER_CREATER_TEXT, main_panel
            )
            if not filter_creator.is_canceled():
                self.length_filter = filter_creator.get_value()
                self.apply_filter_action()

        clear_button = JButton(clear_button_text)
        button_panel.add(clear_button)

        clear_button.addActionListener(lambda e: 
            self.length_filter = None
            self.update_table())

    def enable_length_filter_buttons(self, enabled):
        if apply_button is not None:
            apply_button.set_enabled(enabled)
        
        if clear_button is not None:
            clear_button.set_enabled(enabled)

    def dispose(self):
        filter_table.dispose()
