from typing import List

class ScrollableOptionsEditor:
    def __init__(self, title: str, option_names: List[str] = None):
        self.title = title
        self.option_names = option_names if option_names else []

    @property
    def options_panel(self) -> 'JPanel':
        return self._options_panel

    @options_panel.setter
    def options_panel(self, value: 'JPanel'):
        self._options_panel = value

    @property
    def scroll_pane(self) -> 'JScrollPane':
        return self._scroll_pane

    @scroll_pane.setter
    def scroll_pane(self, value: 'JScrollPane'):
        self._scroll_pane = value

    @property
    def listener(self):
        return self._listener

    @listener.setter
    def listener(self, value):
        self._listener = value

    def dispose(self) -> None:
        if self.options_panel is not None:
            self.options_panel.dispose()

    def apply(self) -> None:
        self.options_panel.apply()

    def cancel(self) -> None:
        pass  # nothing to do

    def reload(self) -> None:
        pass  # nothing to do, as this component is reloaded when options are changed

    def get_editor_component(self, options: 'Options', factory: 'EditorStateFactory') -> 'JComponent':
        self.scroll_pane = JScrollPane()
        self.options_panel = OptionsEditorPanel(self.title, options, self.option_names, factory)
        self.options_panel.set_options_property_change_listener(self.listener)

        outer_panel = JPanel(MiddleLayout())
        outer_panel.add(self.options_panel)
        self.scroll_pane.set_viewport_view(outer_panel)

        return self.scroll_pane

    def set_options_property_change_listener(self, listener: 'PropertyChangeListener') -> None:
        self.listener = listener
        if self.options_panel is not None:
            self.options_panel.set_options_property_change_listener(listener)

class ScollableOptionsPanel(JPanel):
    def __init__(self) -> None:
        super().__init__(MiddleLayout())

    @property
    def preferred_scrollableViewport_size(self) -> 'Dimension':
        return self.get_preferred_size()

    @preferred_scrollableViewport_size.setter
    def preferred_scrollableViewport_size(self, value: 'Dimension'):
        pass  # not implemented

    def get_scrollable_block_increment(self, visible_rect: 'Rectangle', orientation: int, direction: int) -> int:
        return visible_rect.height

    def get_scrollable_tracks_viewport_height(self) -> bool:
        my_size = self.get_preferred_size()
        view_size = self.scroll_pane.get_viewport().get_size()
        view_is_larger = view_size.height > my_size.height
        return view_is_larger

    def get_scrollable_tracks_viewport_width(self) -> bool:
        my_size = self.get_preferred_size()
        view_size = self.scroll_pane.get_viewport().get_size()
        view_is_larger = view_size.width > my_size.width
        return view_is_larger

    def get_scrollable_unit_increment(self, visible_rect: 'Rectangle', orientation: int, direction: int) -> int:
        return 10


# for testing
def get_component(self) -> 'JComponent':
    return self.scroll_pane
