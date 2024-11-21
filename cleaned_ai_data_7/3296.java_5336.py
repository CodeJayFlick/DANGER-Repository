class ViewChangedPluginEvent:
    NAME = "ViewChanged"

    def __init__(self, source: str, tree_name: str, view_set):
        self.source = source
        self.tree_name = tree_name
        self.view_set = view_set

    @property
    def get_tree_name(self) -> str:
        return self.tree_name

    @property
    def get_view(self) -> set:
        return self.view_set

    def __str__(self):
        return f"Tree Name={self.tree_name}, AddressSet={self.view_set}"
