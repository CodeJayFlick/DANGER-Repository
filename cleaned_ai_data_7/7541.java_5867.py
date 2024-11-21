from enum import Enum

class NavigationHistoryChoices(Enum):
    NAVIGATION_EVENTS = "Navigation Events"
    VERTEX_CHANGES = "Vertex Changes"

    def __init__(self, display_name: str) -> None:
        self.display_name = display_name

    def __str__(self) -> str:
        return self.display_name
