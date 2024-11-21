class SaveArchiveAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Save", plugin.name)

    @property
    def popup_menu_data(self):
        return MenuData(["Save Archive"], None, "File")

    @property
    def enabled(self):
        return True

    def is_add_to_popup(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False
        
        selection_paths = self.get_selection_paths(context)
        
        if len(selection_paths) == 0:
            return False
        
        for path in selection_paths:
            node = path[-1]
            if not (isinstance(node, FileArchiveNode) or isinstance(node, ProjectArchiveNode)):
                return False
        
        return True

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False
        
        selection_paths = self.get_selection_paths(context)
        
        return self.should_be_enabled(selection_paths)

    def get_selection_paths(self, context):
        context_object = context.context_object
        gtree = GTree(context_object)
        return gtree.selection_paths

    def should_be_enabled(self, selection_paths):
        for path in selection_paths:
            node = path[-1]
            if self.can_save(node):
                return True
        
        return False

    def can_save(self, node):
        if isinstance(node, (FileArchiveNode, ProjectArchiveNode)):
            archive_node = ArchiveNode(node)
            archive = archive_node.archive
            return archive.is_changed() and archive.is_savable()
        
        return False

    def action_performed(self, context):
        gtree = GTree(context.context_object)

        selection_paths = self.get_selection_paths(context)
        for path in selection_paths:
            node = path[-1]
            if isinstance(node, ArchiveNode):
                archive_node = ArchiveNode(node)
                archive = archive_node.archive
                if archive.is_changed():
                    self.save_archive(archive)

    def save_file_archive(self, file_archive):
        try:
            file_archive.save()
        except IOException as ioe:
            Msg.show_error(self, "Unable to Save File", f"Unexpected exception attempting to save archive: {file_archive}", ioe)

    def save_project_archive(self, project_archive):
        dtm_handler = self.plugin.data_type_manager_handler
        dtm_handler.save(project_archive.domain_object)

    def save_archive(self, archive):
        if isinstance(archive, ProjectArchive):
            self.save_project_archive(archive)
        elif isinstance(archive, FileArchive):
            self.save_file_archive(archive)
        else:
            raise ValueError(f"{archive.name} must be a Project or File archive.")
