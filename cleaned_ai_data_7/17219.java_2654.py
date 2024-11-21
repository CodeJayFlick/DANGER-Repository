class FromComponent:
    def __init__(self):
        self.prefix_list = []

    def add_prefix_table_path(self, prefix_path: list) -> None:
        self.prefix_list.append(prefix_path)

    def get_prefix_paths(self) -> list:
        return self.prefix_list
