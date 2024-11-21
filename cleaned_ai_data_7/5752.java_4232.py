class FSBRootNode:
    def __init__(self, fs_ref):
        self.fs_ref = fs_ref
        self.prev_node = None
        self.sub_root_nodes = []
        self.model_node = self

    @property
    def name(self):
        if self.model_node.fs_ref is not None and not self.model_node.fs_ref.is_closed():
            return self.model_node.fs_ref.filesystem.name
        else:
            return "Missing"

    @property
    def tooltip(self):
        return self.name

    def clone(self):
        clone = FSBRootNode(None)
        if hasattr(clone, 'fs_ref'):
            delattr(clone, 'fs_ref')
        return clone

    def dispose(self):
        self.release_fs_refs_if_model_node()
        super().dispose()

    def swap_back_prev_model_node_and_dispose(self):
        if self != self.model_node:
            self.model_node.swap_back_prev_model_node_and_dispose()
            return
        index_in_parent = self.get_index_in_parent()
        parent = self.get_parent()
        parent.remove_node(self)
        parent.add_node(index_in_parent, self.prev_node)
        self.dispose()  # releases the fs_ref

    def get_fs_ref(self):
        return self.model_node.fs_ref

    def release_fs_refs_if_model_node(self):
        if self != self.model_node:
            return
        for sub_fsb_root_node in self.sub_root_nodes:
            sub_fsb_root_node.release_fs_refs_if_model_node()
        self.sub_root_nodes.clear()

        FileSystemService.get_instance().release_filesystem_immediate(self.fs_ref)
        self.fs_ref = None

    def update_file_attributes(self, monitor):
        if self != self.model_node:
            self.model_node.update_file_attributes(monitor)
            return
        for node in self.get_children():
            monitor.check_cancelled()
            if isinstance(node, FSBFileNode):
                node.update_file_attributes(monitor)

    @property
    def is_leaf(self):
        return False

    def generate_children(self, monitor):
        if self.fs_ref:
            try:
                return [FSBNode.create_node_from_file_list(self.fs_ref.filesystem.get_listing(None), monitor)]
            except IOException as e:
                FSUtilities.display_exception(self, None, "Error Opening File System", "Problem generating children at root of file system", e)
        else:
            return []

    @property
    def fsrl(self):
        return self.model_node.fs_ref.filesystem.get_fsrl()
