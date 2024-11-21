import ghidra_framework as gfh

class ProjectDataReadOnlyAction(gfh.ProjectDataContextToggleAction):
    def __init__(self, owner, group):
        super().__init__("Read-Only", owner)
        self.set_popup_menu_data({"Read-Only": {"group": group}})
        self.selected = False
        self.mark_help_unnecessary()

    @gfh.action_performed
    def actionPerformed(self, context: gfh.ProjectDataContext) -> None:
        file = next(iter(context.get_selected_files()))
        self.toggle_read_only(file)
        if isinstance(context.get_context_object(), gfh.DomainFileNode):
            node = cast(gfh.DomainFileNode, context.get_context_object())
            node.fire_node_changed(node.parent, node)

    @gfh.is_add_to_popup
    def is_add_to_popup(self, context: gfh.ProjectDataContext) -> bool:
        if not context.in_active_project():
            return False

        if context.folder_count != 0 or context.file_count != 1:
            return False

        file = next(iter(context.get_selected_files()))
        self.selected = file.is_read_only()
        return True

    @gfh.is_enabled_for_context
    def is_enabled_for_context(self, context: gfh.ProjectDataContext) -> bool:
        if context.folder_count != 0 or context.file_count != 1:
            return False

        file = next(iter(context.get_selected_files()))
        return not file.is_versioned()

    @gfh.toggle_read_only
    def toggle_read_only(self, file: gfh.DomainFile) -> None:
        try:
            file.set_read_only(not file.is_read_only())
        except Exception as e:
            gfh.Msg.show_error(None, "Error setting read-only state for {}".format(file.name), str(e))
