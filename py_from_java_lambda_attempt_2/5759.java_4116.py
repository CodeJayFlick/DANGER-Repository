Here is the translation of the Java code into Python:

```Python
class BatchImportDialog:
    def __init__(self):
        self.batch_info = None
        self.destination_folder = None
        self.program_manager = None
        self.strip_leading = True
        self.strip_container = False
        self.open_after_importing = False

    @staticmethod
    def show_and_import(tool, batch_info, initial_files, default_folder, program_manager):
        dialog = BatchImportDialog(batch_info, default_folder)
        dialog.set_program_manager(program_manager)

        SystemUtilities.run_swing_later(lambda: 
            dialog.build()
            if initial_files and len(initial_files) > 0:
                dialog.add_sources(initial_files)
            else:
                return
            tool.show_dialog(dialog))

    def build(self):
        self.table_model = BatchImportTableModel(self.batch_info)
        table = GTable(self.table_model)

        # Turn off all grid lines - this is a problem on windows.
        table.set_show_grid(False)
        table.set_intercell_spacing(Dimension(0, 0))

        selected_column = table.get_column_model().get_column(BatchImportTableModel.COLS.SELECTED.ordinal())
        selected_column.set_resizable(False)

        # TODO: automagically get necessary col width
        selected_column.set_max_width(50)

        files_column = table.get_column_model().get_column(BatchImportTableModel.COLS.FILES.ordinal())

        cell_editor = self.create_files_column_cell_editor()
        files_column.set_cell_editor(cell_editor)
        files_column.set_cell_renderer(self.create_files_column_cell_renderer())

        lang_column = table.get_column_model().get_column(BatchImportTableModel.COLS.LANG.ordinal())
        cell_editor = self.create_lang_column_cell_editor()
        lang_column.set_cell_editor(cell_editor)
        lang_column.set_cell_renderer(self.create_lang_column_cell_renderer())

        scrollPane = JScrollPane(table)

        filesPanel = JPanel()
        filesPanel.setLayout(BorderLayout())
        filesPanel.add(scrollPane, BorderLayout.CENTER)
        filesPanel.setBorder(create_titledBorder("Files to Import", True))

        sourceListPanel = JPanel()
        sourceListPanel.setLayout(BorderLayout())
        sourceListPanel.set_border(create_titledBorder("Import Sources", False))

        self.source_list_model = SourcesListModel()

        list = JList(self.source_list_model)
        list.setName("batch.import.source.list")
        list.add_list_selection_listener(lambda e: 
            if not e.get_value_is_adjusting():
                has_selection = len(list.get_selected_indices()) > 0
                remove_source_button.set_enabled(has_selection)

        sourceListScrollPane = JScrollPane(list)
        sourceListPanel.add(sourceListScrollPane, BorderLayout.CENTER)

        maxDepthPanel = JPanel()
        label = GDLabel("Depth limit:")
        tip = "Maximum container (ie. nested zip, tar, etc) depth in the source file to recursively descend into"
        label.set_tooltip_text(tip)

        spinner_number_model = SpinnerNumberModel(self.batch_info.get_max_depth(), 0, 99, 1)
        self.max_depth_spinner = JSpinner(spinner_number_model)
        self.max_depth_spinner.set_tooltip_text(tip)

        rescan_button = JButton("Rescan")
        tip = "Clear Files to Import list and rescan Import Sources for applications to import"
        rescan_button.set_tooltip_text(tip)

        spinner_number_model.add_change_listener(lambda e: 
            if not (spinner_number_model.get_number().get_value() == self.batch_info.get_max_depth()):
                rescan_button.set_enabled(True)
            else:
                rescan_button.set_enabled(False))

        maxDepthPanel.add(self.max_depth_spinner)
        maxDepthPanel.add(rescan_button)

        buttonWrapperPanel = JPanel()
        buttonWrapperPanel.add(sourceListButtonsPanel, BorderLayout.EAST)

        outputOptionsPanel = self.build_output_options_panel()

        box = Box.create_vertical_box()
        box.add(sourceListPanel)
        box.add(filesPanel)
        box.add(outputOptionsPanel)

        add_ok_button()
        add_cancel_button()

        add_work_panel(box)

    def create_files_column_cell_editor(self):
        combo_box = JComboBox()
        default_cell_editor = DefaultCellEditor(combo_box) 
        return cell_editor

    def create_lang_column_cell_renderer(self):
        table_cell_renderer = GTableCellRenderer() 
        return cell_renderer

    # ... rest of the code
```

Note that Python does not have direct equivalents for Java's Swing and AWT libraries, so some parts may need to be rewritten or replaced.