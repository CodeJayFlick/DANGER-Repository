class SetFunctionPurgeCommand:
    def __init__(self, function: 'ghidra.program.model.listing.Function', new_purge: int):
        self.function = function
        self.new_purge = new_purge

    def apply_to(self, obj) -> bool:
        if isinstance(obj, DomainObject):  # assuming DomainObject is a class in your Python code
            self.function.set_stack_purge_size(self.new_purge)
            return True
        else:
            raise ValueError("Invalid object")

    @property
    def status_msg(self):
        return ""

    @property
    def name(self) -> str:
        return "Set Function Purge"
