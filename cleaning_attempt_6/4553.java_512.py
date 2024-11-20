class MarkerService:
    SELECTION_PRIORITY = 100
    HIGHLIGHT_PRIORITY = 50
    CHANGE_PRIORITY = -50
    GROUP_PRIORITY = -25
    CURSOR_PRIORITY = 200
    FUNCTION_COMPARE_CURSOR_PRIORITY = 49
    SEARCH_PRIORITY = 75
    BREAKPOINT_PRIORITY = 50
    BOOKMARK_PRIORITY = 0
    PROPERTY_PRIORITY = 75
    DIFF_PRIORITY = 80
    REFERENCE_PRIORITY = -10

    HIGHLIGHT_GROUP = "HIGHLIGHT_ GROUP"

    def __init__(self):
        self.marker_sets = {}
        self.change_listeners = []
        self.marker_clicked_listener = None

    def create_area_marker(self, name: str, marker_description: str, program: 'Program', priority: int,
                           show_markers: bool, show_navigation: bool, color_background: bool, color: tuple):
        return MarkerSet(name, marker_description, program, priority, show_markers, show_navigation, color_background, color)

    def create_area_marker(self, name: str, marker_description: str, program: 'Program', priority: int,
                           show_markers: bool, show_navigation: bool, color_background: bool, color: tuple, is_preferred: bool):
        return MarkerSet(name, marker_description, program, priority, show_markers, show_navigation, color_background, color)

    def create_point_marker(self, name: str, marker_description: str, program: 'Program', priority: int,
                            show_markers: bool, show_navigation: bool, color_background: bool, color: tuple, icon: 'ImageIcon'):
        return MarkerSet(name, marker_description, program, priority, show_markers, show_navigation, color_background, color)

    def create_point_marker(self, name: str, marker_description: str, program: 'Program', priority: int,
                            show_markers: bool, show_navigation: bool, color_background: bool, color: tuple, icon: 'ImageIcon', is_preferred: bool):
        return MarkerSet(name, marker_description, program, priority, show_markers, show_navigation, color_background, color)

    def remove_marker(self, marker_set: 'MarkerSet', program: 'Program'):
        pass  # Not implemented in Python

    def get_marker_set(self, name: str, program: 'Program') -> 'MarkerSet':
        return self.marker_sets.get(name) if name else None

    def set_marker_for_group(self, group_name: str, marker_set: 'MarkerSet', program: 'Program'):
        pass  # Not implemented in Python

    def remove_marker_for_group(self, group_name: str, marker_set: 'MarkerSet', program: 'Program'):
        pass  # Not implemented in Python

    def get_background_color(self, address: int) -> tuple:
        for markerset in self.marker_sets.values():
            if markerset.contains(address):
                return markerset.get_background_color()
        return None

    def add_change_listener(self, listener: callable):
        self.change_listeners.append(listener)

    def remove_change_listener(self, listener: callable):
        self.change_listeners.remove(listener)

    def set_marker_clicked_listener(self, listener: 'MarkerClickedListener'):
        if self.marker_clicked_listener:
            raise ValueError("A marker clicked listener is already set.")
        else:
            self.marker_clicked_listener = listener
