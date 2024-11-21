class ExporterDialog:
    def __init__(self, tool, domain_file):
        self.tool = tool
        self.domain_file = domain_file
        self.current_selection = None
        self.options_button = None
        self.selection_checkbox = None
        self.file_path_text_field = None
        self.file_chooser_button = None

    def show_options(self):
        options_validator = lambda x: get_selected_exporter().set_options(x)
        options_dialog = OptionsDialog(options=self.options, validator=options_validator, parent=self)
        tool.show_dialog(options_dialog)

    def selected_format_changed(self):
        exporter = get_selected_exporter()
        if exporter:
            self.options = exporter.get_options(lambda: get_domain_object(TaskMonitor.DUMMY))
        validate()

    def update_selection_checkbox(self):
        should_enable_checkbox = should_enable_checkbox()
        selection_checkbox.set_enabled(should_enable_checkbox)

    def do_open_file(self, task_monitor):
        try:
            domain_object = domain_file.get_immutable_domain_object(self, DomainFile.DEFAULT_VERSION, TaskMonitor.DUMMY)
        except (VersionException, CancelledException, IOException) as e:
            Msg.error(self, "Error Opening File", str(e))

    def get_address_factory(self):
        dobj = self.do_open_file(TaskMonitor.DUMMY)
        if isinstance(dobj, Program):
            return dobj.get_address_factory()
        return None

    def try_export(self, task_monitor):
        exporter = get_selected_exporter()

        exporter.set_exporter_service_provider(tool)
        domain_object = self.do_open_file(task_monitor)

        if not domain_object:
            return False
        program_selection = self.applicable_program_seletion()
        output_file = self.get_selected_output_file()

        try:
            if output_file.exists() and OptionDialog.show_option_dialog(self, "Overwrite Existing File?", f"The file {output_file} already exists. Do you want to overwrite it?", "Overwrite", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE:
                return False
            if self.options is not None:
                exporter.set_options(self.options)
            success = exporter.export(output_file, domain_object, program_selection, task_monitor)
            display_summary_results(exporter, domain_object)
            return success
        except Exception as e:
            Msg.error(self, "Exception exporting", str(e))

    def get_applicable_program_seletion(self):
        if self.selection_checkbox.isSelected():
            return self.current_selection
        return None

    # Other methods...

class OptionsDialog:
    def __init__(self, options, validator, parent):
        self.options = options
        self.validator = validator
        self.parent = parent

    def get_options(self):
        return self.options

# Other classes...
