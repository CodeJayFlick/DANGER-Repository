class ProgramTreeSelectionPlugin:
    def __init__(self):
        self.select_module_action = None

    def create_actions(self):
        if not hasattr(self, 'select_module_action'):
            self.select_module_action = TreeSelectAction("ProgramTreeSelectionPlugin")
            # Add the action to a tool or plugin here
            pass

    def select_module(self, context):
        address_set = set()
        node = context.get_context_object()

        tree = node['tree']
        count = len(tree.selection_paths)
        paths = tree.selection_paths
        for i in range(count):
            path = paths[i]
            p_node = path[-1]['node']
            self._get_address_set(p_node, address_set)

        selection = ProgramSelection(address_set)
        pspe = ProgramSelectionPluginEvent("Selection", selection, node['program'])
        # Fire the plugin event here
        pass

    def _get_address_set(self, group, set):
        if isinstance(group, 'ProgramFragment'):
            set.add(group)
        else:
            groups = group.children
            for group2 in groups:
                self._get_address_set(group2, set)

class TreeSelectAction:
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    @property
    def popup_menu_data(self):
        return MenuData(["Select Addresses"], None, "select")

    @property
    def help_location(self):
        return HelpLocation(HelpTopics.PROGRAM_TREE, "SelectAddresses")

    def is_enabled_for_context(self, context):
        active_obj = context.get_context_object()
        if isinstance(active_obj, 'ProgramNode'):
            return active_obj['program'] is not None
        return False

    def action_performed(self, context):
        self.select_module(context)

class ProgramSelection:
    def __init__(self, address_set):
        super().__init__()
        self.address_set = address_set

class ProgramSelectionPluginEvent:
    def __init__(self, topic, selection, program):
        super().__init__()
        self.topic = topic
        self.selection = selection
        self.program = program
