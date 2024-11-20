class SelectAllAction:
    def __init__(self, owner, panel):
        self.panel = panel
        super().__init__("Select All", owner)
        self.set_key_binding_data(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK)

        help_location = HelpLocation(HelpTopics.SELECTION, self.get_name())
        self.set_help_location(help_location)

    def perform_action(self, context):
        self.panel.select_all()
