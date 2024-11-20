class MarkupItemFilterDialogComponentProvider:
    def __init__(self, controller, dialog_model):
        super().__init__()
        self.controller = controller
        self.dialog_model = dialog_model
        self.set_help_location("VersionTrackingPlugin", "Markup_Filters")

    def build_filter_panel(self):
        row_one_panel = JPanel()
        row_one_panel.setLayout(BoxLayout(row_one_panel, BoxLayout.X_AXIS))

        # status filter
        status_filter = MarkupStatusFilter()
        self.add_filter(status_filter)
        row_one_panel.add(status_filter.get_component())

        # markup type
        type_filter = MarkupTypeFilter()
        self.add_filter(type_filter)
        row_one_panel.add(type_filter.get_component())

        return row_one_panel

class JPanel:
    def __init__(self):
        pass

    def set_layout(self, layout):
        pass

    def add(self, component):
        pass

class BoxLayout:
    X_AXIS = 0
    Y_AXIS = 1

    def __init__(self, panel, axis):
        self.panel = panel
        self.axis = axis

    def get_panel(self):
        return self.panel

    def set_axis(self, axis):
        self.axis = axis

class MarkupStatusFilter:
    def __init__(self):
        pass

    def get_component(self):
        pass

class MarkupTypeFilter:
    def __init__(self):
        pass

    def get_component(self):
        pass
