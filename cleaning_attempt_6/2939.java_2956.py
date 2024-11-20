class SampleSearchTableProvider:
    def __init__(self, plugin: 'SampleSearchTablePlugin', searcher):
        self.plugin = plugin
        self.component = build(searcher)
        set_transient()

    @staticmethod
    def build(searcher):
        panel = JPanel(BorderLayout())
        panel.setBorder(EmptyBorder(3, 3, 3, 3))

        model = SampleSearchTableModel(searcher, plugin.get_tool())
        filter_table = GhidraFilterTable(model)
        table = filter_table.get_table()

        if goTo_service := plugin.get_tool().get_service(GoToService):
            table.install_navigation(go_to_service, go_to_service.get_default_navigatable())

        table.set_navigate_on_selection_enabled(True)

        panel.add(filter_table)

        return panel

    def dispose(self):
        self.filter_table.dispose()
        self.filter_table.get_table().dispose()
        self.remove_from_tool()

    @property
    def component(self):
        return self.component

    def options_changed(self, tool_options: 'ToolOptions', option_name: str, old_value: object, new_value: object):
        # TODO Auto-generated method stub
