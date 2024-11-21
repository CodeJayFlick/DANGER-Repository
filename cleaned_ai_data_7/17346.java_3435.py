class ShowChildPathsPlan:
    def __init__(self, show_content_type: str, prefix_path: 'PartialPath') -> None:
        self.show_content_type = show_content_type
        self.prefix_path = prefix_path
        self.can_be_split = False

    @property
    def path(self) -> 'PartialPath':
        return self.prefix_path


class PartialPath:
    pass  # This is a placeholder, you may need to implement this class further depending on your use case.
