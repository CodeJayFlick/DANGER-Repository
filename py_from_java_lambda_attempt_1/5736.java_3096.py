Here is a translation of the Java code into Python:

```Python
class ImporterPlugin:
    def __init__(self):
        self.import_action = None
        self.import_selection_action = None
        self.add_to_program_action = None
        self.chooser = None
        self.front_end_service = None

    def init(self, tool):
        super().__init__()
        self.front_end_service = tool.get_front_end_service()
        if self.front_end_service is not None:
            self.front_end_service.add_project_listener(self)

        self.setup_import_action(tool)
        self.setup_batch_import_action(tool)
        self.setup_import_selection_action(tool)
        self.setup_add_to_program_action()

    def read_config_state(self, save_state):
        super().read_config_state(save_state)
        paths = save_state.get_strings("library search paths", None)
        if paths is not None:
            LibrarySearchPathManager.set_library_paths(paths)

    def write_config_state(self, save_state):
        super().write_config_state(save_state)
        paths = LibrarySearchPathManager.get_library_paths()
        save_state.put_strings("library search paths", paths)

    def dispose(self):
        super().dispose()
        if self.import_action is not None:
            self.import_action.dispose()
        if self.import_selection_action is not None:
            self.import_selection_action.dispose()
        if self.add_to_program_action is not None:
            self.add_to_program_action.dispose()
        if self.front_end_service is not None:
            self.front_end_service.remove_project_listener(self)
        self.chooser = None

    def process_event(self, event):
        super().process_event(event)

        if isinstance(event, ProgramActivatedPluginEvent):
            program = event.get_active_program()
            self.import_selection_action.set_enabled(program is not None)
            self.add_to_program_action.set_enabled(program is not None)

    def import_files(self, dest_folder, files):
        BatchImportDialog.show_and_import(tool, None, [self.files2fsrls(file) for file in files], dest_folder, tool.get_service(ProgramManager))

    def files2fsrls(self, files):
        if files is None:
            return []
        result = []
        for f in files:
            result.append(FileSystemService.getInstance().get_local_fsrl(f))
        return result

    def import_file(self, folder, file):
        fsrl = FileSystemService.getInstance().get_local_fsrl(file)
        program_manager = tool.get_service(ProgramManager)
        ImporterUtilities.show_import_dialog(tool, program_manager, fsrl, folder, None)

    def project_closed(self, project):
        if self.import_action is not None:
            self.import_action.set_enabled(False)
        if self.import_selection_action is not None:
            self.import_selection_action.set_enabled(False)
        if self.add_to_program_action is not None:
            self.add_to_program_action.set_enabled(False)

    def project_opened(self, project):
        if self.import_action is not None:
            self.import_action.set_enabled(True)
        if self.import_selection_action is not None:
            self.import_selection_action.set_enabled(False)
        if self.add_to_program_action is not None:
            self.add_to_program_action.set_enabled(False)

    def setup_import_action(self, tool):
        title = "Import File"
        self.import_action = DockingAction(title, self.__class__.__name__)
        self.import_action.action_performed = lambda context: self.do_single_import_action(get_folder_from_context(context))
        self.import_action.is_valid_context = lambda context: True
        self.import_action.set_menu_bar_data(MenuData(new_string_array=["&File", title + "..."], None, "Import", MenuData.NO_MNEMONIC, 1))
        self.import_action.set_key_binding_data(KeyBindingData(KeyEvent.VK_I, InputEvent.CTRL_DOWN_MASK | InputEvent.ALT_DOWN_MASK))

    def setup_batch_import_action(self):
        title = "Batch Import"
        self.batch_import_action = DockingAction(title, self.__class__.__name__)
        self.batch_import_action.action_performed = lambda context: BatchImportDialog.show_and_import(tool, None, [], get_folder_from_context(context), tool.get_service(ProgramManager))
        self.batch_import_action.is_valid_context = lambda context: True
        self.batch_import_action.set_menu_bar_data(MenuData(new_string_array=["&File", title + "..."], None, "Import", MenuData.NO_MNEMONIC, 2))

    def setup_import_selection_action(self):
        title = "Extract and Import"
        self.import_selection_action = DockingAction(title, self.__class__.__name__)
        self.import_selection_action.action_performed = lambda context: self.do_import_selection_action(get_folder_from_context(context))
        self.import_selection_action.is_valid_context = lambda context: True
        self.import_selection_action.set_menu_bar_data(MenuData(new_string_array=[title + "..."], None, "Import", MenuData.NO_MNEMONIC, 3))

    def setup_add_to_program_action(self):
        title = "Add To Program"
        self.add_to_program_action = DockingAction(title, self.__class__.__name__)
        self.add_to_program_action.action_performed = lambda context: self.do_add_to_program()
        self.add_to_program_action.is_valid_context = lambda context: True
        self.add_to_program_action.set_menu_bar_data(MenuData(new_string_array=["&File", title + "..."], None, "Import", MenuData.NO_MNEMONIC, 4))

    def get_folder_from_context(self, context):
        if isinstance(context, DomainFolderNode):
            return context.get_domain_folder()
        else:
            return AppInfo.getActive_project().get_root_folder()

    def initialize_chooser(self, title, button_text, multi_select):
        if self.chooser is None:
            self.chooser = GhidraFileChooser(tool.get_active_window())
            self.chooser.add_file_filter(ImporterUtilities.LOADABLE_FILES_FILTER)
            self.chooser.set_selected_file_filter(GhidraFileFilter.ALL)

    def do_single_import_action(self, folder):
        # Implementation of the import action

    def do_add_to_program(self):
        # Implementation of the add to program action

    def do_import_selection_action(self, selection):
        if selection is None or selection.get_num_address_ranges() != 1:
            return
        range = selection.get_first_range()
        if range.get_length() >= (Integer.MAX_VALUE & 0xffffffffL):
            Msg.show_info(self.__class__, tool.get_active_window(), "Selection Too Large", "The selection is too large to extract.")
            return

    # Implementation of the import file action