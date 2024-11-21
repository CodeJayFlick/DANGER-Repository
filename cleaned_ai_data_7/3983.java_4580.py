class SearchDirectionWidget:
    def __init__(self, title, dialog):
        self.dialog = dialog
        self.search_direction = "forward"

    @property
    def search_direction(self):
        return self._search_direction

    @search_direction.setter
    def search_direction(self, value):
        if value not in ["forward", "backward"]:
            raise ValueError("Invalid direction")
        self._search_direction = value


class ForwardSearchAction:
    def __init__(self, dialog):
        self.dialog = dialog

    def actionPerformed(self, event):
        self.dialog.message_panel.clear()
        return


class BackwardSearchAction(ForwardSearchAction):
    pass


def create_search_rb(action, name, tooltip):
    button = GRadioButton(action)
    button.set_text(name)
    button.set_tooltip_text(tooltip)
    return button
