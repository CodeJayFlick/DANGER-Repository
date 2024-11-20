Here is the translation of the given Java code into Python:

```Python
class IndependentColorProvider:
    VERTEX_COLORS = "VERTEX_ COLORS"

    def __init__(self):
        self.recent_color_cache = RecentColorCache()
        self.tool = None

    def using_custom_colors(self) -> bool:
        return True

    def get_color_from_user(self, start_color: tuple[int, int, int]) -> tuple[int, int, int]:
        new_color = GhidraColorChooser().show_dialog(start_color)
        if new_color and new_color != start_color:
            self.recent_color_cache.add_color(new_color)
            return new_color
        else:
            return start_color

    def get_active_component(self) -> Component | None:
        manager = DockingWindowManager.get_instance()
        placeholder = manager.get_focused_component()
        if placeholder is not None:
            return placeholder.component
        else:
            return manager.active_component

    def set_vertex_color(self, vertex: FGVertex, new_color: tuple[int, int, int]) -> None:
        vertex.set_background_color(new_color)

    def clear_vertex_color(self, vertex: FGVertex) -> None:
        vertex.clear_color()

    def get_most_recent_color(self) -> tuple[int, int, int]:
        return self.recent_color_cache.get_most_recent_color()

    def get_recent_colors(self) -> list[tuple[int, int, int]]:
        return self.recent_color_cache.get_mru_color_list()

    def save_plugin_colors(self, save_state: SaveState) -> None:
        colors_element = Element(VERTEX_COLORS)
        for color in recent_color_cache:
            element = Element("COLOR")
            element.set_attribute("RGB", str(color))
            colors_element.add_content(element)
        save_state.put_xml_element(VERTEX_COLORS, colors_element)

    def load_plugin_colors(self, save_state: SaveState) -> None:
        xml_element = save_state.get_xml_element(VERTEX_COLORS)
        if xml_element is not None:
            color_elements = xml_element.get_children("COLOR")
            for element in color_elements:
                rgb_string = element.get_attribute_value("RGB")
                rgb = int(rgb_string, 16)
                self.recent_color_cache.add_color((rgb // (2 ** 22), (rgb >> 18) & 0xFF, (rgb >> 10) & 0xFF))

    def save_vertex_colors(self, vertex: FGVertex, settings: FunctionGraphVertexAttributes) -> None:
        user_defined_color = vertex.get_user_defined_color()
        if user_defined_color is not None:
            settings.put_vertex_color(vertex.vertex_address, user_defined_color)

    def load_vertex_colors(self, vertex: FGVertex, settings: FunctionGraphVertexAttributes) -> None:
        saved_color = settings.get_vertex_color(vertex.vertex_address)
        if saved_color is not None:
            vertex.restore_color(saved_color)


class RecentColorCache(dict):
    MAX_SIZE = 10
    most_recent_color = (0, 0, 255)

    def __init__(self):
        super().__init__()
        self.max_size = 16

    def add_color(self, color: tuple[int, int, int]) -> None:
        self[color] = color
        self.most_recent_color = color

    def get_mru_color_list(self) -> list[tuple[int, int, int]]:
        return sorted(list(self.keys()), reverse=True)

    def get_most_recent_color(self) -> tuple[int, int, int]:
        return self.most_recent_color


class GhidraColorChooser:
    def __init__(self):
        pass

    def show_dialog(self, start_color: tuple[int, int, int]) -> tuple[int, int, int] | None:
        # This method should be implemented
        pass
```

Please note that the `GhidraColorChooser` class is not fully implemented in this translation. It would require a GUI library like Tkinter or PyQt to create a color chooser dialog.