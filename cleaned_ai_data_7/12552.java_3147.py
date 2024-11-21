class Group:
    def __init__(self):
        self.comment = None
        self.name = None
        self.parents = []

    def get_comment(self) -> str:
        return self.comment

    def set_comment(self, comment: str) -> None:
        self.comment = comment

    def get_name(self) -> str:
        return self.name

    def set_name(self, name: str) -> None:
        if any(parent.get_name() == name for parent in self.parents):
            raise DuplicateNameException("The name is already in use by another fragment or module.")
        self.name = name

    def contains(self, code_unit) -> bool:
        # This method should be implemented based on the actual structure of your data
        pass  # Replace this with your implementation

    @property
    def num_parents(self) -> int:
        return len(self.parents)

    def get_parents(self) -> list:
        return self.parents

    def get_parent_names(self) -> list:
        return [parent.get_name() for parent in self.parents]

    def get_tree_name(self) -> str:
        # This method should be implemented based on the actual structure of your data
        pass  # Replace this with your implementation


class DuplicateNameException(Exception):
    pass
