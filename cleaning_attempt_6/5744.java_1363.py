class FileSystemBrowserComponentProvider:
    def __init__(self, plugin: 'FileSystemBrowserPlugin', fs_ref):
        self.plugin = plugin
        self.root_node = FSBRootNode(fs_ref)
        super().__init__(plugin.get_tool(), fs_ref.filesystem.name, plugin.name)

        set_transient()
        set_icon(ImageManager.PHOTO)

        self.g_tree = GTree(self.root_node)
        self.g_tree.selection_model.set_selection_mode(TreeSelectionModel.DISCONTIGUOUS_TREE_SELECTION)
        self.g_tree.selection_model.add_tree_selection_listener(lambda e: tool.context_changed(self))
        for path in self.g_tree.get_selection_paths():
            if len(path) == 1:
                clicked_node = GTreeNode(path[-1])
                handle_single_click(clicked_node)

        self.g_tree.add_mouse_listener(GMouseListenerAdapter(
            lambda e: double_click_triggered(e),
            lambda e: mouse_clicked(e)
        ))

    def get_g_tree(self):
        return self.g_tree

    def get_fsrl(self) -> 'FSRL':
        if self.root_node:
            return self.root_node.get_fsrl()
        else:
            return None

    def dispose(self):
        if self.root_node and not self.root_node.fs_ref.is_closed():
            self.root_node.fs_ref.filesystem.ref_manager.remove_listener(self)
        remove_from_tool()
        if action_manager is not None:
            action_manager.dispose()
            action_manager = None
        if g_tree is not None:
            g_tree.dispose()  # calls dispose on tree's root node, which will release the fs_refs
            g_tree = None
        self.root_node = None
        self.plugin = None

    def after_added_to_tool(self):
        action_manager.register_component_actions_in_tool()

    @staticmethod
    def quick_show_program(fsrl) -> bool:
        if plugin.has_program_manager():
            program_manager = FSBUtils.get_program_manager(plugin.get_tool(), False)
            if program_manager is not None:
                consumer = object()
                program = ProgramMappingService.find_matching_open_program(fsrl, consumer)
                if program is not None:
                    program_manager.set_current_program(program)
                    program.release(consumer)
                    return True
        return False

    def handle_single_click(self, clicked_node):
        if isinstance(clicked_node, FSBFileNode):
            node = clicked_node
            if node.fs_rl is not None:
                self.quick_show_program(node.fs_rl)
                update_password_status(node)

    @staticmethod
    def update_password_status(node):
        # currently this is the only state that might change and affect the node display

class GMouseListenerAdapter:
    def __init__(self, double_click_triggered=None, mouse_clicked=None):
        self.double_click_triggered = double_click_triggered
        self.mouse_clicked = mouse_clicked

    @staticmethod
    def double_click_triggered(e) -> None:
        pass  # TODO: implement this method

    @staticmethod
    def mouse_clicked(e) -> None:
        pass  # TODO: implement this method


class FSBActionManager:
    def __init__(self, plugin, provider, text_editor_service, g_tree):
        self.plugin = plugin
        self.provider = provider
        self.text_editor_service = text_editor_service
        self.g_tree = g_tree

    @staticmethod
    def action_open_programs_action_performed(action_context) -> None:
        pass  # TODO: implement this method


class FSBRootNode(GTreeNode):
    def __init__(self, fs_ref):
        super().__init__()
        self.fs_rl = fs_ref.filesystem.get_fsrl()
