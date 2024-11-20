class PreviousSelectedRangeAction:
    def __init__(self, tool, owner_name, nav_options):
        super().__init__(tool, "Previous Selected Range", owner_name, nav_options)

        icon = ResourceManager.load_image("images/PreviousSelectionBlock16.gif")
        self.set_menu_bar_data({"menu": ["Navigation", "Previous Selected Range"], 
                                "icon": icon, 
                                "category": PluginCategoryNames.NAVIGATION,
                                "mnemonic": None})

        self.set_tool_bar_data({"toolbar_group": 3, 
                               "action_sub_group": NextPrevSelectedRangePlugin.ACTION_SUB_GROUP, 
                               "icon": icon})
        
        key_binding = {"key_event": KeyEvent.VK_CLOSE_BRACKET, 
                       "modifiers": [InputEvent.SHIFT_DOWN_MASK] | [DockingUtils.CONTROL_KEY_MODIFIER_MASK]}
        self.set_key_binding_data(key_binding)

        self.setDescription("Go to previous selected range")
        help_location = HelpLocation(HelpTopics.SELECTION, self.getName())
        self.setHelpLocation(help_location)
        
    def get_selection(self, context):
        return context.get_selection()
