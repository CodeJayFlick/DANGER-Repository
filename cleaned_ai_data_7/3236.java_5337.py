class CreateFragmentCmd:
    def __init__(self, tree_name: str, name: str, parent_name: str):
        self.tree_name = tree_name
        self.name = name
        self.parent_name = parent_name
        self.status_msg = ""

    def apply_to(self, obj) -> bool:
        program = obj  # assuming Program is a class in the same module as CreateFragmentCmd
        listing = program.get_listing()
        module = listing.get_module(self.tree_name, self.parent_name)
        if module is None:
            self.status_msg = f"Module named {self.parent_name} does not exist"
            return False

        try:
            module.create_fragment(self.name)
            return True
        except Exception as e:  # assuming DuplicateNameException in Python would be a subclass of Exception
            self.status_msg = f"{self.name} already exists"

    def get_status_msg(self) -> str:
        return self.status_msg

    def get_name(self) -> str:
        return "Create Fragment"
