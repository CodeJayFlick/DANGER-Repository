Here is the translation of the Java code into Python:

```Python
class GhidraColorChooser:
    DEFAULT_TITLE = "Please Choose a Color"

    def __init__(self):
        pass

    def __init__(self, initial_color=None):
        if initial_color is not None:
            super().__init__(initial_color)

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        self._title = value

    def set_color_history(self, colors):
        for color in colors:
            recent_color_cache.add_color(color)

    def get_color_history(self):
        return list(recent_color_cache.values())

    def set_active_tab(self, tab_name):
        self.active_tab_name = tab_name

    @property
    def active_tab_name(self):
        return self._active_tab_name

    def show_dialog(self, center_over_component):
        maybe_install_settable_color_swatch_chooser_panel()
        ok_listener = OKListener()
        dialog = create_dialog(center_over_component, self.title, True, self, ok_listener)
        do_set_active_tab(dialog)

        dialog.show()  # blocks until user brings dialog down...
        color = ok_listener.get_color()
        if color is not None:
            recent_color_cache.add_color(color)
        return color

    def find_tabbedPane(self, component):
        if not isinstance(component, Container):
            return None
        parent = container(component)

        if isinstance(parent, JTabbedPane):
            return parent
        for i in range(len(parent.get_components())):
            child = parent.get_component(i)
            pane = self.find_tabbedPane(child)
            if pane is not None:
                return pane

    def maybe_install_settable_color_swatch_chooser_panel(self):
        if recent_color_cache.size == 0:
            return
        mru_color_list = list(recent_color_cache.values())
        chooser_panels = get_chooser_panels()
        if len(chooser_panels) > 1 and isinstance(chooser_panels[0], SettableColorSwatchChooserPanel):
            panel = chooser_panels[0]
            panel.set_recent_colors(mru_color_list)
            return
        new_swatch_panel = SettableColorSwatchChooserPanel(mru_color_list)
        new_chooser_panels = [new_swatch_panel] + list(chooser_panels[1:])
        self.set_chooser_panels(new_chooser_panels)

    def do_set_active_tab(self, dialog):
        if self.active_tab_name is None:
            return
        pane = find_tabbedPane(dialog)
        if pane is not None and len(pane.get_titles()) > 0:
            for i in range(len(pane.get_titles())):
                tab_title = pane.get_title(i)
                if self.active_tab_name == tab_title:
                    pane.set_selected_index(i)
                    return

    def create_dialog(self, center_over_component, title, modal, owner, listener):
        pass

class OKListener:
    def __init__(self):
        self.ok_color = None

    def action_performed(self, event):
        self.ok_color = GhidraColorChooser.this.get_color()

    @property
    def get_color(self):
        return self.ok_color


class RecentColorCache(dict):
    MAX_SIZE = 15

    def __init__(self):
        super().__init__()

    def add_color(self, color):
        self[color] = color

    def get_mru_color_list(self):
        list_ = sorted(list(self.keys()), reverse=True)
        return [color for color in list_]