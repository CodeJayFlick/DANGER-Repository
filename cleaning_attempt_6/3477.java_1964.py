class ComputeChecksumsProvider:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__()
        self.checksums = []
        self.has_results = False
        self.main_panel = None
        self.error_status = None

        # Initialize checksum algorithms
        from ghidra.ghidra import ChecksumAlgorithm
        for algorithm in ChecksumAlgorithm.__subclasses__():
            self.checksums.append(algorithm())

    def get_component(self):
        return self.main_panel

    def create_work_panel(self):
        initialize_table()
        main = JPanel()

        # Set up the layout and add components to it
        main.setLayout(BorderLayout())
        results_main_panel = JPanel(FlowLayout())
        results_main_panel.setBorder(TitledBorder("Checksum Results"))
        table_panel = JPanel(FlowLayout())
        scroll = JScrollPane(table)
        table_panel.add(scroll, BorderLayout.CENTER)
        main.add(results_main_panel, BorderLayout.CENTER)

        self.error_status = GDLabel(" ")
        self.error_status.setName("message")
        self.error_status.setHorizontalAlignment(SwingConstants.CENTER)
        self.error_status.setForeground(Color.RED)
        self.error_status.setBorder(EmptyBorder(0, 5, 0, 5))
        main.add(self.error_status, BorderLayout.SOUTH)

        return main

    def generate(self):
        if not self.plugin.get_program() or not self.is_visible():
            return
        task = ComputeChecksumTask(self, self.plugin.get_program().get_memory(), do_on_selection())
        TaskLauncher(task, self.main_panel)
        if task.has_error():
            set_error_message(task.get_error_message())

    def generate_checksum_completed(self):
        self.has_results = True
        update_fields()

    def set_selection(self, state):
        set_error_message("")
        selection_action.set_selected(state)
        selection_action.setEnabled(state)
        if state:
            generate()
        else:
            clear_fields()

    # ... other methods ...

class ComputeChecksumTask(TaskLauncher):
    pass

# Initialize table and checksums
def initialize_table():
    model = ChecksumTableModel(tool, checksums)
    table = GhidraTable(model)

# Set up actions
compute_action = DockingAction("Compute Checksum", plugin_name())
compute_action.set_help_location(HelpLocation("ComputeChecksumsPlugin", "compute"))
compute_action.setEnabled(True)
compute_action.set_tool_bar_data(ToolBarData(Icons.REFRESH_ICON, None))
compute_action.setDescription("Refreshes checksums")

# ... other actions ...

def update_fields():
    if not self.has_results:
        return
    model.set_format_options(show_hex_action.isSelected())
    model.fire_table_data_changed()

def clear_fields():
    for check_result in checksums:
        check_result.reset()
    model.fire_table_data_changed()

class DockingAction(ActionContext):
    pass

# ... other classes and methods ...
