class PreviousHighlightedRangeAction:
    def __init__(self, tool, owner, nav_options):
        super().__init__(tool, "Previous Highlighted Range", owner, nav_options)
        self.set_menu_bar_data({
            'menu': ['Navigation', 'Previous Highlight Range'],
            'image': 'images/PreviousHighlightBlock16.gif',
            'category': PluginCategoryNames.NAVIGATION,
            'mnemonic': None
        })
        self.set_tool_bar_data({
            'image': 'images/PreviousHighlightBlock16.gif',
            'group': ToolConstants.TOOLBAR_GROUP_THREE,
            'sub_group': NextPrevHighlightRangePlugin.ACTION_SUB_GROUP
        })
        self.set_key_binding_data({
            'key_event': KeyEvent.VK_9,
            'modifier_mask': DockingUtils.CONTROL_KEY_MODIFIER_MASK
        })

    def set_description(self, description):
        return f"Go to previous highlighted range: {description}"

    def get_help_location(self):
        return HelpLocation(HelpTopics.HIGHLIGHT, self.get_name())

class ProgramSelection:
    pass

def main():
    tool = None  # Replace with actual plugin tool
    owner = None  # Replace with actual owner
    nav_options = None  # Replace with actual navigation options
    action = PreviousHighlightedRangeAction(tool, owner, nav_options)
