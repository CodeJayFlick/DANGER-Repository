class CloneDecompilerAction:
    def __init__(self):
        super().__init__("Decompile Clone")
        image = ResourceManager.load_image("images/camera-photo.png")
        self.set_tool_bar_data(ToolBarData(image, "ZZZ"))
        self.setDescription("Create a snapshot (disconnected) copy of this Decompiler window ")
        help_location = HelpLocation(HelpTopics.DECOMPILER, "ToolBarSnapshot")
        self.set_help_location(help_location)
        key_binding_data = KeyBindingData(KeyEvent.VK_T,
                                            InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)
        self.set_key_binding_data(key_binding_data)

    def is_enabled_for_decompiler_context(self, context):
        return context.get_function() is not None

    def decompiler_action_performed(self, context):
        context.get_component_provider().clone_window()
