class ProjectDataExpandAction:
    def __init__(self, owner: str, group: str, context_class):
        self.owner = owner
        self.group = group
        self.context_class = context_class
        super().__init__("Expand All", owner)

    @property
    def popup_menu_data(self) -> tuple[str]:
        return ("Expand All",), self.group

    def mark_help_unnecessary(self):
        pass  # equivalent to Java's markHelpUnnecessary()

    def action_performed(self, context: "T") -> None:
        tree = context.get_tree()
        paths = context.get_selection_paths()
        if len(paths) > 0:
            path = paths[0]
            self.expand(tree, path)

    @property
    def is_add_to_popup(self, context: "T") -> bool:
        return context.folder_count == 1 and context.file_count == 0

    @property
    def is_enabled_for_context(self, context: "T") -> bool:
        return context.folder_count == 1 and context.file_count == 0

    def expand(self, tree: object, path: tuple) -> None:
        last_component = path[-1]
        if isinstance(last_component, GTreeNode):
            tree.expand_tree(last_component)
