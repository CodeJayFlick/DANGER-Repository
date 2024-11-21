class DefaultGraphDisplayComponentProvider:
    WINDOW_GROUP = "ProgramGraph"
    WINDOW_MENU_GROUP_NAME = "Graph"

    def __init__(self, display):
        self.display = display

    def get_window_sub_menu_name(self):
        return self.WINDOW_MENU_GROUP_NAME

    def get_component(self):
        return self.display.get_component()

    def close_component(self):
        if self.display is not None:
            super().close_component()
            closing_display = self.display
            self.display = None
            closing_display.close()
            self.remove_all_local_actions()

    def get_action_context(self, event):
        return self.display.get_action_context(event)

    def remove_all_local_actions(self):
        super().remove_all_local_actions()


class DefaultGraphDisplay:
    pass


# Example usage:

display = DefaultGraphDisplay()  # You would need to implement this class
provider = DefaultGraphDisplayComponentProvider(display)
