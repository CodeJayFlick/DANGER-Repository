import resources.MultiIcon

class BuiltInArchiveNode:
    def __init__(self, archive: 'BuiltInArchive', filter_state):
        super().__init__(archive, filter_state)

    def get_icon(self, expanded: bool) -> object:
        base_icon = self.archive.get_icon(expanded)
        multi_icon = MultiIcon(base_icon)
        return multi_icon

    def get_tooltip(self) -> str:
        return "Built In Data Types"
