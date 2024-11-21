class RemoveSecondaryHighlightAction:
    NAME = "Remove Secondary Highlight"

    def __init__(self):
        self.set_name(self.NAME)
        self.set_popup_menu_data(["Secondary Highlight", "Remove Highlight"], "Decompile")
        self.set_help_location(HelpTopics.DECOMPILER, "ActionSecondaryHighlight")

    def is_enabled_for_decompiler_context(self, context):
        if not context.has_real_function():
            return False

        token = context.get_token_at_cursor()
        if token is None:
            return False

        panel = context.get_deompiler_panel()
        highlighted_tokens = panel.get_secondary_highlighted_tokens()
        return highlighted_tokens.contains(token)

    def decompiler_action_performed(self, context):
        token = context.get_token_at_cursor()
        panel = context.get_deompiler_panel()
        panel.remove_secondary_highlight(token)
