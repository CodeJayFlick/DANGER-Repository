class RenameTreeCmd:
    def __init__(self, old_name: str, new_name: str):
        self.old_name = old_name
        self.new_name = new_name
        self.program = None
        self.status_msg = ""

    def apply_to(self, obj):
        if isinstance(obj, Program):
            self.program = obj
            listing = self.program.get_listing()
            try:
                listing.rename_tree(self.old_name, self.new_name)
                return True
            except Exception as e:
                self.status_msg = str(e)
        return False

    def get_status_msg(self) -> str:
        return self.status_msg

    def get_name(self) -> str:
        return "Rename Tree View"
