class AbstractVisualVertex:
    def __init__(self):
        self.focused = False
        self.selected = False
        self.hovered = False
        self.alpha = 1.0
        self.emphasis = None
        self.location = None

    def set_focused(self, focused: bool) -> None:
        self.focused = focused

    def is_focused(self) -> bool:
        return self.focused

    def set_selected(self, selected: bool) -> None:
        self.selected = selected

    def is_selected(self) -> bool:
        return self.selected

    def set_hovered(self, hovered: bool) -> None:
        self.hovered = hovered

    def is_hovered(self) -> bool:
        return self.hovered

    def set_emphasis(self, emphasis_level: float) -> None:
        self.emphasis = emphasis_level

    def get_emphasis(self) -> float:
        return self.emphasis

    def set_location(self, location: tuple or list) -> None:
        if isinstance(location, (tuple, list)):
            self.location = location
        else:
            raise TypeError("Location must be a tuple or list")

    def get_location(self) -> tuple or list:
        return self.location

    def set_alpha(self, alpha_value: float) -> None:
        self.alpha = alpha_value

    def get_alpha(self) -> float:
        return self.alpha

    def is_grabbable(self, c=None) -> bool:
        if c is not None and isinstance(c, (tuple, list)):
            # all parts of a vertex are grabbable by default; subclasses can override
            return True
        else:
            raise TypeError("Component must be a tuple or list")
