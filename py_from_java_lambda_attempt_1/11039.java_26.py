Here is the translation of the Java code into Python:

```Python
class ChangeManager:
    def __init__(self, tree_panel):
        self.tree_panel = tree_panel
        self.tree = tree_panel.get_data_tree()
        self.root = self.tree.get_model_root()

    def domain_file_removed(self, parent, name, file_id):
        self.update_folder_node(parent)
        folder_node = self.find_domain_folder_node(parent, True)
        if folder_node is not None:
            children = folder_node.get_children()
            for child in children:
                if isinstance(child, DomainFileNode) and child.name == name:
                    folder_node.remove_node(child)

    def domain_folder_removed(self, parent, name):
        self.update_folder_node(parent)
        folder_path = []
        get_folder_path(parent, folder_path)
        folder_path.append(name)
        folder_node = self.find_domain_folder_node(folder_path, True)
        if folder_node is not None:
            folder_node.get_parent().remove_node(folder_node)

    def domain_folder_renamed(self, folder, old_name):
        self.domain_folder_removed(folder.parent, old_name)
        self.domain_folder_added(folder)

    def domain_file_renamed(self, file, old_name):
        self.domain_file_removed(file.parent, old_name, file.file_id)
        self.domain_file_added(file)

    def domain_folder_moved(self, folder, old_parent):
        self.domain_folder_removed(old_parent, folder.name)
        self.domain_folder_added(folder)

    def domain_file_moved(self, file, old_parent, old_name):
        self.update_folder_node(old_parent)
        self.domain_file_added(file)

    def domain_file_added(self, file):
        if isinstance(file, DomainFile) and not file.is_removed:
            folder = file.parent
            while folder is not None:
                node = self.find_domain_folder_node(folder, True)
                if node is not None:
                    new_node = DomainFileNode(file)
                    add_node(node, new_node)

    def domain_folder_added(self, folder):
        if isinstance(folder, DomainFolder) and not folder.is_removed:
            parent_folder = folder.parent
            while parent_folder is not None:
                node = self.find_domain_folder_node(parent_folder, True)
                if node is not None:
                    new_node = DomainFolderNode(folder, node.domain_file_filter())
                    add_node(node, new_node)

    def domain_folder_set_active(self, folder):
        node = self.find_domain_folder_node(folder, False)
        if node is not None:
            self.tree.set_selected_node(node)

    #def domain_file_saved(self, file, dobj):  # ignored
    pass

    def domain_file_status_changed(self, file, file_id_set):
        if isinstance(file, DomainFile) and not file.is_removed:
            node = self.find_domain_file_node(file, True)
            if node is not None:
                node.refresh()
            self.tree_panel.domain_change()

    def get_folder_path(self, df, list):
        parent = df.parent
        while parent is not None:
            list.append(parent.name)
            parent = parent.parent

    def find_domain_folder_node(self, folder_path, lazy=False):
        if len(folder_path) == 0:
            return self.root
        node = self.find_domain_folder_node([folder_path[0]])
        for name in folder_path[1:]:
            found = False
            children = list(node.get_children())
            for child in children:
                if isinstance(child, DomainFolderNode):
                    if child.name == name:
                        node = child
                        found = True
                        break
            if not found and lazy is False:
                return None  # not visited 
        return node

    def find_domain_file_node(self, file, lazy=False):
        folder_path = []
        get_folder_path(file.parent, folder_path)
        folder_path.append(file.name)
        node = self.find_domain_folder_node(folder_path, lazy)
        if node is not None:
            children = list(node.get_children())
            for child in children:
                if isinstance(child, DomainFileNode):
                    return child
        return None

    def update_folder_node(self, parent):
        folder_node = self.find_domain_folder_node(parent, True)
        if folder_node is not None:
            domain_folder = folder_node.domain_folder()
            # loop through children looking for nodes whose underlying model object does not have this folder as its parent;
            children = list(folder_node.get_children())
            for child in children:
                if isinstance(child, DomainFileNode):
                    file = child.file
                    if file is None or file.parent != domain_folder:
                        folder_node.remove_node(child)
                elif isinstance(child, DomainFolderNode):
                    folder = child.domain_folder()
                    if folder is None or folder != domain_folder:
                        folder_node.remove_node(child)

    #def domain_file_object_replaced(self, file, old_object):  # ignored
    pass

    def domain_file_object_opened_for_update(self, file, object):
        # ignored
        pass

    def domain_file_object_closed(self, file, object):
        # ignored
        pass