class SetSecondaryHighlightAction:
    NAME = "Set Secondary Highlight"

    def __init__(self):
        super().__init__(NAME)
        self.set_popup_menu_data(["Secondary Highlight", "Set Highlight"], "Decompile")

    def decompiler_action_performed(self, context):
        token = context.get_token_at_cursor()
        context.get_deompiler_panel().add_secondary_highlight(token)

if __name__ == "__main__":
    pass
