class RemoveInvalidArchiveFromProgramAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Remove Invalid Archive", plugin.name)
        set_popup_menu_data([
            {"text": "Remove Archive From Program"},
        ])
        description("Removes the archive from program and tool")
        enabled(True)

    @property
    def is_enabled(self):
        if not isinstance(context, DataTypesActionContext):
            return False

        context_object = context.get_context_object()
        gtree = GTree(context_object)
        selection_paths = gtree.get_selection_paths()

        if len(selection_paths) != 1:
            return False

        path = selection_paths[0]
        node = path.get_last_path_component()
        return isinstance(node, InvalidArchiveNode)

    def perform_action(self):
        context = self.context
        gtree = GTree(context.get_context_object())

        selection_paths = gtree.get_selection_paths()

        if len(selection_paths) != 1:
            return

        path_component = selection_paths[0].get_last_path_component()
        invalid_archive_node = InvalidArchiveNode(path_component)

        response = OptionDialog.show_option_dialog(
            gtree,
            "Confirm Remove Invalid Archive(s)",
            f"Are you sure you want to delete archive: {invalid_archive_node.name} from the program?<br><br>(WARNING: This action will disassociate all datatypes in the program from this archive.)",
            "Yes", OptionDialog.QUESTION_MESSAGE
        )

        if response != OptionDialog.ONE:
            return

        archive = invalid_archive_node.get_archive()
        data_type_manager_handler = self.plugin.data_type_manager_handler
        data_type_manager_handler.remove_invalid_archive(archive)
