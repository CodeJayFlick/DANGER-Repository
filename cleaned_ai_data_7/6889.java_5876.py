class BackwardsSliceAction:
    NAME = "Highlight Backward Slice"

    def __init__(self):
        super().__init__("Highlight Backward Slice")
        self.set_help_location(HelpLocation("DECOMPILER", "ActionHighlight"))
        self.set_popup_menu_data(MenuData(["Highlight", "Backward Slice"], "Decompile"))

    def is_enabled_for_decompiler_context(self, context):
        token_at_cursor = context.get_token_at_cursor()
        varnode = DecompilerUtils().get_varnode_ref(token_at_cursor)
        return varnode is not None

    def decompiler_action_performed(self, context):
        token_at_cursor = context.get_token_at_cursor()
        varnode = DecompilerUtils().get_varnode_ref(token_at_cursor)
        if varnode is None:
            return
        panel = context.get_decompiler_panel()
        panel.clear_primary_highlights()

        op = token_at_cursor.get_pcode_op()
        backward_slice = DecompilerUtils().get_backward_slice(varnode)
        color_provider = SliceHighlightColorProvider(panel, backward_slice, varnode, op)
        panel.add_varnode_highlights(backward_slice, color_provider)

class MenuData:
    def __init__(self, items, label):
        self.items = items
        self.label = label

class HelpLocation:
    def __init__(self, topic, help_topic):
        self.topic = topic
        self.help_topic = help_topic

# Assuming these classes are defined elsewhere in the codebase
DecompilerUtils()
SliceHighlightColorProvider()

