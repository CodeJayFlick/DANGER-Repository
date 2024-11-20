class FunctionGraphViewSettings:
    def __init__(self):
        self.location = None
        self.selection = None
        self.highlight = None
        self.info = {}

    def set_location(self, location):
        self.location = location

    def set_selection(self, selection):
        self.selection = selection

    def set_highlight(self, highlight):
        self.highlight = highlight

    def set_function_graph_perspective_info(self, info):
        self.info = info

    @property
    def location(self):
        return self.location

    @location.setter
    def location(self, value):
        self.location = value

    @property
    def selection(self):
        return self.selection

    @selection.setter
    def selection(self, value):
        self.selection = value

    @property
    def highlight(self):
        return self.highlight

    @highlight.setter
    def highlight(self, value):
        self.highlight = value

    @property
    def function_graph_perspective_info(self):
        return self.info

    @function_graph_perspective_info.setter
    def function_graph_perspective_info(self, value):
        self.info = value


class FunctionGraphViewSettingsCopy(FunctionGraphViewSettings):

    def __init__(self, copy_settings: 'FunctionGraphViewSettings'):
        super().__init__()
        if isinstance(copy_settings, FunctionGraphViewSettings):
            self.location = copy_settings.location
            self.selection = copy_settings.selection
            self.highlight = copy_settings.highlight
            self.info = copy_settings.info

