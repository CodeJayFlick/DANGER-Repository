class FieldPanelCoordinator:
    def __init__(self, panels):
        self.panels = list(panels)
        for panel in self.panels:
            self.addListeners(panel)

    def dispose(self):
        for panel in self.panels:
            self.removeListeners(panel)
        self.panels = None

    def add(self, fp):
        self.addListeners(fp)
        self.panels.append(fp)
        viewer_position = fp.get_viewer_position()
        self.view_changed(fp, viewer_position[0], viewer_position[1], viewer_position[2])

    def remove(self, fp):
        self.removeListeners(fp)
        self.panels.remove(fp)

    def view_changed(self, fp, index, x_offset, y_offset):
        if not hasattr(self, 'values_changing') or getattr(self, 'values_changing'):
            return
        try:
            for panel in self.panels:
                if panel != fp:
                    panel.set_viewer_position(index, x_offset, y_offset)
        finally:
            setattr(self, 'values_changing', False)

    def addListeners(self, fp):
        fp.add_view_listener(self)

    def removeListeners(self, fp):
        fp.remove_view_listener(self)


class BigInteger:  # Python doesn't have a built-in equivalent to Java's BigInteger
    pass


if __name__ == "__main__":
    class FieldPanel:
        def get_viewer_position(self):  # This method is not defined in the original code
            return [1, 2, 3]  # Replace this with actual implementation

        def set_viewer_position(self, index, x_offset, y_offset):
            pass  # Replace this with actual implementation

    class ViewerPosition:
        def __init__(self, index, x_offset, y_offset):
            self.index = index
            self.xOffset = x_offset
            self.yOffset = y_offset

    panels = [FieldPanel() for _ in range(5)]
    coordinator = FieldPanelCoordinator(panels)
