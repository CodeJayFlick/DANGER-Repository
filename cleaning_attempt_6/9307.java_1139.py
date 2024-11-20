class ToggleDockingAction:
    SELECTED_STATE_PROPERTY = "selectState"

    def __init__(self):
        pass

    def is_selected(self) -> bool:
        """Returns True if the toggle state for this action is currently selected."""
        raise NotImplementedError("Subclasses must implement isSelected")

    def set_selected(self, value: bool) -> None:
        """Sets the toggle state for this action."""
        raise NotImplementedError("Subclasses must implement setSelected")
