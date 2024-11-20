class NextPrevHighlightRangePlugin:
    def __init__(self):
        self.nav_options = NavigationOptions()
        self.next_action = None
        self.prev_action = None

    def create_actions(self):
        if not self.next_action:
            self.next_action = NextHighlightedRangeAction(None, "Next Highlighted Range", self.nav_options)
        if not self.prev_action:
            self.prev_action = PreviousHighlightedRangeAction(None, "Previous Highlighted Range", self.nav_options)

class NavigationOptions:
    def __init__(self):
        pass

    def dispose(self):
        pass

class NextHighlightedRangeAction:
    def __init__(self, tool, name, nav_options):
        self.tool = tool
        self.name = name
        self.nav_options = nav_options

class PreviousHighlightedRangeAction:
    def __init__(self, tool, name, nav_options):
        self.tool = tool
        self.name = name
        self.nav_options = nav_options
