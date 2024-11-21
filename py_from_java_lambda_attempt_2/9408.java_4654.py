Here is a translation of your Java code into equivalent Python:

```Python
class DockingMenuItemUI:
    TABULATOR_PROPERTIES = "menuItemTabulator"
    COLUMN_PADDING = 20

    def __init__(self):
        self.ui = None

    @staticmethod
    def create_ui(c):
        result = DockingMenuItemUI()
        result.ui = UIManager.get_defaults().get_ui(c)
        return result

    def install_ui(self, c):
        if self.ui is not None:
            self.ui.install_ui(c)

    def uninstall_ui(self, c):
        if self.ui is not None:
            self.ui.uninstall_ui(c)

    def paint(self, g, c):
        if ((c.get_text()).index('\t') != -1):
            tabulator = MenuTabulator.get(c)
            sg = SwitchGraphics2D(g)
            sg.set_do_draw(False)
            sg.set_do_fill(True)
            sg.set_do_text(True)
            sg.set_do_image(False)

            self.ui.paint(sg, c)

            self._paint_text(sg, c, tabulator)

        else:
            self.ui.paint(g, c)

    def update(self, g, c):
        if ((c.get_text()).index('\t') != -1):
            tabulator = MenuTabulator.get(c)
            sg = SwitchGraphics2D(g)
            sg.set_do_draw(False)
            sg.set_do_fill(True)
            sg.set_do_text(True)
            sg.set_do_image(False)

            self.ui.update(sg, c)

            self._paint_text(sg, c, tabulator)

        else:
            self.ui.update(g, c)

    def _paint_text(self, g, c, t):
        orig_icon = c.get_icon()
        icon_width = 0
        if orig_icon is not None:
            icon_width = orig_icon.get_icon_width()

        orig_text = c.get_text()
        parts = orig_text.split('\t')
        for i in range(len(parts)):
            c.set_text(parts[i])
            self.ui.paint(g, c)

            g.translate(icon_width + t.columns[i] + self.COLUMN_PADDING, 0)
            icon_width = 0
            c.set_icon(None)
            c.set_accelerator(None)

    def get_preferred_size(self, c):
        ui_pref = self.ui.get_preferred_size(c)
        text = (c.get_text())
        if text.index('\t') == -1:
            return ui_pref

        extra = ui_pref.width - self._text_width(c, text)
        tabulator = MenuTabulator.tabulate(c)

        return Dimension(tabulator.width + extra, ui_pref.height)

    def get_minimum_size(self, c):
        return self.ui.get_minimum_size(c)

    def get_maximum_size(self, c):
        return self.ui.get_maximum_size(c)

    def _text_width(self, c, text):
        return GraphicsUtils.string_width(c, c.font_metrics(), text)

class MenuTabulator:
    columns = []

    @staticmethod
    def tabulate(c):
        if not hasattr(c, 'get_client_property'):
            return None

        p = (c.get_parent())
        prop = p.get_client_property(DockingMenuItemUI.TABULATOR_PROPERTIES)
        if prop is None or isinstance(prop, MenuTabulator):
            return prop

        c.put_client_property(DockingMenuItemUI.TABULATOR_PROPERTIES, MenuTabulator())

    @staticmethod
    def get(c):
        return (c.get_parent()).get_client_property(DockingMenuItemUI.TABULATOR_PROPERTIES)

class SwitchGraphics2D:
    do_draw = True
    do_fill = True
    do_text = True
    do_image = True

    def __init__(self, g):
        self.g = g

    def set_do_draw(self, b):
        self.do_draw = b

    def set_do_fill(self, b):
        self.do_fill = b

    def set_do_text(self, b):
        self.do_text = b

    def set_do_image(self, b):
        self.do_image = b

class GraphicsUtils:
    @staticmethod
    def string_width(c, fm, text):
        return fm.string_width(text)
```

This Python code is equivalent to your Java code.