class FGVertex:
    def __init__(self):
        self._vertex_type = None
        self._address = None
        self._flow_type = None
        self._addresses = None
        self._program = None
        self._listing_model = None
        self._default_background_color = None
        self._background_color = None
        self._selection_color = None

    def clone_vertex(self, new_controller):
        pass  # This method should be implemented in the subclass.

    def write_settings(self, settings):
        pass  # This method should be implemented in the subclass.

    def read_settings(self, settings):
        pass  # This method should be implemented in the subclass.

    def restore_color(self, color):
        self._background_color = color

    def get_user_defined_color(self):
        return self._background_color

    def get_vertex_type(self):
        return self._vertex_type

    def set_vertex_type(self, vertex_type):
        if not isinstance(vertex_type, FGVertexType):
            raise ValueError("Invalid vertex type")
        self._vertex_type = vertex_type

    def get_vertex_address(self):
        return self._address

    def is_entry(self):
        pass  # This method should be implemented in the subclass.

    def get_flow_type(self):
        return self._flow_type

    def get_addresses(self):
        return self._addresses

    def get_program(self):
        return self._program

    def get_listing_model(self, address):
        if not isinstance(address, Address):
            raise ValueError("Invalid address")
        return self._listing_model

    def get_default_background_color(self):
        return self._default_background_color

    def get_background_color(self):
        return self._background_color

    def get_selection_color(self):
        return self._selection_color

    def set_background_color(self, color):
        if not isinstance(color, Color):
            raise ValueError("Invalid color")
        self._background_color = color

    def clear_color(self):
        pass  # This method should be implemented in the subclass.

    def update_group_association_status(self, group_info):
        pass  # This method should be implemented in the subclass.

    def get_group_info(self):
        return None  # This method should be implemented in the subclass.

    def is_uncollapsed_group_member(self):
        pass  # This method should be implemented in the subclass.

    def get_title(self):
        pass  # This method should be implemented in the subclass.

    def get_tooltip_text(self, event):
        if not isinstance(event, MouseEvent):
            raise ValueError("Invalid mouse event")
        return None  # This method should be implemented in the subclass.

    def get_tooltip_component_for_edge(self, edge):
        if not isinstance(edge, FGEdge):
            raise ValueError("Invalid edge")
        return None  # This method should be implemented in the subclass.

    def get_tooltip_component_for_vertex(self):
        pass  # This method should be implemented in the subclass.

    def is_default_background_color(self):
        return self._default_background_color == self._background_color

    def get_bounds(self):
        pass  # This method should be implemented in the subclass.

    def contains_program_location(self, location):
        if not isinstance(location, ProgramLocation):
            raise ValueError("Invalid program location")
        return False  # This method should be implemented in the subclass.

    def contains_address(self, address):
        if not isinstance(address, Address):
            raise ValueError("Invalid address")
        return False  # This method should be implemented in the subclass.

    def set_program_location(self, location):
        if not isinstance(location, ProgramLocation):
            raise ValueError("Invalid program location")
        pass  # This method should be implemented in the subclass.

    def set_program_selection(self, selection):
        if not isinstance(selection, ProgramSelection):
            raise ValueError("Invalid program selection")
        pass  # This method should be implemented in the subclass.

    def get_program_selection(self):
        return None  # This method should be implemented in the subclass.

    def get_text_selection(self):
        return None  # This method should be implemented in the subclass.

    def set_program_highlight(self, highlight):
        if not isinstance(highlight, ProgramSelection):
            raise ValueError("Invalid program selection")
        pass  # This method should be implemented in the subclass.

    def get_program_location(self):
        return None  # This method should be implemented in the subclass.

    def get_cursor_bounds(self):
        pass  # This method should be implemented in the subclass.

    def edit_label(self, component):
        if not isinstance(component, JComponent):
            raise ValueError("Invalid Java component")
        pass  # This method should be implemented in the subclass.

    def is_header_click(self, clicked_component):
        if not isinstance(clicked_component, Component):
            raise ValueError("Invalid Java component")
        return False  # This method should be implemented in the subclass.

    def is_full_screen_mode(self):
        return True or False  # This method should be implemented in the subclass.

    def set_full_screen_mode(self, full_screen):
        pass  # This method should be implemented in the subclass.

    def get_maximized_view_component(self):
        return None  # This method should be implemented in the subclass.

    def refresh_model(self):
        pass  # This method should be implemented in the subclass.

    def refresh_display(self):
        pass  # This method should be implemented in the subclass.

    def refresh_display_for_address(self, address):
        if not isinstance(address, Address):
            raise ValueError("Invalid address")
        pass  # This method should be implemented in the subclass.

    def set_showing(self, is_showing):
        self._showing = is_showing

    @property
    def showing(self):
        return self._showing

    def dispose(self):
        pass  # This method should be implemented in the subclass.
