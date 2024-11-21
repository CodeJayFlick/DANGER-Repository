class ProjectDataSelectAction:
    def __init__(self, owner, group):
        self.owner = owner
        self.group = group
        super().__init__("Select All", owner)
        self.set_popup_menu_data(self.get_group(), ["Select Children"])
        self.mark_help_unnecessary()

    @property
    def popup_menu_data(self):
        return {"menu_items": self.get_group()}

    def action_performed(self, context):
        tree = context.tree
        paths = context.selection_paths
        node = paths[0].get_last_component()
        if isinstance(node, GTreeNode):
            self.select_all_children(tree, node)

    @property
    def add_to_popup(self):
        return lambda context: context.get_folder_count() == 1 and context.get_file_count() == 0

    def select_all_children(self, tree, node):
        paths = []
        self.get_all_tree_paths(node, paths)
        tree.set_selection_paths(paths)

    def get_all_tree_paths(self, node, paths):
        paths.append(node.tree_path)
        children = node.children
        for child in children:
            self.get_all_tree_paths(child, paths)


class GTreeNode:
    pass


class DataTree:
    @property
    def selection_paths(self):
        return []

    def set_selection_paths(self, paths):
        pass

    @property
    def tree_path(self):
        pass
