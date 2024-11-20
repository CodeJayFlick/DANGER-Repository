class FocusOwnerProvider:
    def __init__(self):
        pass

    def get_focus_owner(self) -> object:
        """Returns the current focus owner"""
        raise NotImplementedError("Subclasses must implement this method")

    def get_active_window(self) -> object:
        """Returns the active window"""
        raise NotImplementedError("Subclasses must implement this method")
