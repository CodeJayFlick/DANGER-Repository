class JgtNamedLayoutProvider:
    def __init__(self, layout_name):
        self.layout_name = layout_name

    def get_layout_name(self):
        return self.layout_name

    def get_action_icon(self):
        return None  # no good icon

    def get_priority_level(self):
        return 75  # low priority than other layouts; other layouts use 200, 101 and 100

    def get_fg_layout(self, graph, monitor):
        try:
            layout = JgtNamedLayout(graph, self.layout_name)
            layout.set_task_monitor(monitor)
            return layout
        except Exception as e:
            raise CancelledException from e

    def __str__(self):
        return self.layout_name


class JgtNamedLayout:
    def __init__(self, graph, name):
        self.graph = graph
        self.name = name

    def set_task_monitor(self, monitor):
        pass  # no implementation for now

# Example usage:
provider = JgtNamedLayoutProvider("my_layout")
print(provider.get_layout_name())  # prints "my_layout"
