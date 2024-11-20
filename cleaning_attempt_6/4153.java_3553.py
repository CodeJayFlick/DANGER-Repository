class DnDMoveManager:
    def __init__(self, tree):
        self.tree = tree
        self.reorder_dd_mgr = ReorderManager(tree)

    def is_drop_site_ok(self, destination_node, drop_nodes, drop_action, relative_mouse_pos):
        for i in range(len(drop_nodes)):
            if not self.can_drop_node(destination_node, drop_nodes[i], drop_action, relative_mouse_pos):
                return False
        return True

    def can_drop_node(self, destination_node, drop_node, drop_action, relative_mouse_position):
        drag_group = drop_node.get_group()
        if drag_group == destination_node.get_group():
            return False  # Can't drop a group onto itself
        
        if relative_mouse_position != 0:
            return self.reorder_dd_mgr.is_drop_site_ok(destination_node, drop_node, drop_action, relative_mouse_position)

        if destination_node.is_fragment():
            return self.check_dest_fragment(destination_node, drop_node, drop_action)
        
        dest_module = destination_node.get_module()
        if drop_node.is_fragment() and dest_module.contains(drop_node.get_fragment()):
            return False
        
        if drop_node.is_module():
            drop_module = drop_node.get_module()
            if dest_module.contains(drop_module):
                return False
            if drop_module.is_descendant(dest_module):
                return False
        
        return True

    def add(self, destination_node, drop_nodes, drop_action, relative_mouse_pos):
        if relative_mouse_pos != 0:
            self.reorder_dd_mgr.add(destination_node, drop_nodes, drop_action, relative_mouse_pos)
            return
        
        operation = "Move" if drop_action == DnDConstants.ACTION_MOVE else "Copy"
        transaction_id = self.tree.start_transaction(operation)
        
        try:
            for i in range(len(drop_nodes)):
                ok = True
                if destination_node.is_fragment():
                    ok = self.add_to_fragment(destination_node, drop_nodes[i])
                else:
                    self.add_to_module(destination_node, drop_nodes[i], drop_action)
                
                if ok:
                    self.tree.add_selection_path(destination_node.get_tree_path())
        
        finally:
            self.tree.end_transaction(transaction_id, True)

    def check_dest_fragment(self, destination_node, drop_node, drop_action):
        if drop_action != DnDConstants.ACTION_MOVE:
            return False
        
        if drop_node.is_fragment():
            return True  # Fragment -> Fragment means Merge Fragments
        else:
            parent_module = drop_node.get_parent_module()
            if parent_module.is_descendant(destination_node.get_fragment()):
                return False
            return True

    def add_to_fragment(self, destination_node, drop_node):
        dest_frag = destination_node.get_fragment()
        
        try:
            self.tree.merge_group(drop_node.get_group(), dest_frag)
            self.tree.remove_selection_path(drop_node.get_tree_path())
            return True
        
        except Exception as e:
            Msg.show_error(None, None, "Error", "Error Moving Fragments", e)
        
        return False

    def add_to_module(self, destination_node, drop_node, drop_action):
        dest_module = destination_node.get_module()
        parent_module = drop_node.get_parent_module()

        if not destination_node.was_visited():
            self.tree.visit_node(destination_node)

        if drop_node.is_fragment():
            fragment = drop_node.get_fragment()
            if drop_action == DnDConstants.ACTION_COPY:
                dest_module.add(fragment)
            else:
                dest_module.reparent(fragment.name, parent_module)
        
        elif drop_node.is_module():
            module = drop_node.get_module()
            if drop_action == DnDConstants.ACTION_COPY:
                dest_module.add(module)
            else:
                dest_module.reparent(module.name, parent_module)

            if self.tree.is_expanded(destination_node.get_tree_path()):
                self.tree.group_added(module)  # need to add the group now so that the expansion can be matched

        newnode = self.tree.child(destination_node, drop_node.name)
        if newnode is not None:
            self.tree.match_expansion_state(drop_node, newnode)

class ReorderManager:
    def __init__(self, tree):
        self.tree = tree
    
    def is_drop_site_ok(self, destination_node, drop_node, drop_action, relative_mouse_position):
        # implementation
        pass

    def add(self, destination_node, drop_nodes, drop_action, relative_mouse_pos):
        # implementation
        pass
