class ProgramTreeModelListener:
    def __init__(self, tree):
        self.tree = tree

    def tree_nodes_changed(self, e):
        node = e.path[-1]
        if isinstance(node, tuple) and len(node) > 0:
            node = node[0]

        new_name = str(node).strip()
        if not new_name:
            node.set_user_object(node.name)
            self.tree.rename()
            return

        group = node.get_group()
        old_name = group.name
        if new_name == old_name:
            return  # name hasn't changed

        cmd = RenameCmd(self.tree.name, isinstance(group, ProgramModule), old_name, new_name)
        if self.tree.tool.execute(cmd, self.tree.program):
            self.tree.name_indexer.remove(old_name)
            self.tree.name_indexer.put(new_name)

        else:
            node.set_user_object(node.name)
            Msg.show_error("Rename Failed", cmd.status_msg())
            self.tree.rename()

        self.tree.setEditable(False)


    def tree_nodes_inserted(self, e):
        path = list(e.path)
        me = list(e.children)

        child_path = [x for x in path] + [me[0]]
        node = ProgramNode(me[0])
        node.set_tree_path(TreePath(child_path))

        self.tree.group_path = node
    def tree_nodes_removed(self, e):
        pass

    def tree_structure_changed(self, e):
        pass


class TreeModelEvent:
    def __init__(self, path=None, children=None):
        self.path = path if isinstance(path, list) else []
        self.children = children if isinstance(children, list) else []

    @property
    def get_tree_path(self):
        return self.path

    @property
    def getChildIndices(self):
        return [0]  # assuming only one child


class TreePath:
    def __init__(self, path=None):
        self.path = path if isinstance(path, list) else []

    @property
    def getLastPathComponent(self):
        return self.path[-1]


class ProgramNode:
    def __init__(self, node):
        self.node = node

    @property
    def getUserObject(self):
        return str(self.node)

    @property
    def getName(self):
        return str(self.node)

    @property
    def getGroup(self):
        # assuming this method returns the group object based on the node
        pass

    @property
    def setTreePath(self, path):
        self.path = path


class RenameCmd:
    def __init__(self, name, is_module, old_name, new_name):
        self.name = name
        self.is_module = is_module
        self.old_name = old_name
        self.new_name = new_name

    @property
    def getStatusMsg(self):
        return f"Rename failed: {self.old_name} to {self.new_name}"


class Msg:
    @staticmethod
    def show_error(title, parent, message, detail=None):
        print(f"{title}: {message}{f' ({detail})' if detail else ''}")
