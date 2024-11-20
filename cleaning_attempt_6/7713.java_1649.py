class FcgFunction:
    def __init__(self, name, entry):
        self.called_functions = set()
        self.calling_functions = set()
        self.entry = entry

    def add_called_function(self, f):
        self.called_functions.add(f)

    def add_caller_function(self, f):
        self.calling_functions.add(f)

    def get_entry_point(self):
        return self.entry

    def get_called_functions(self):
        return frozenset(self.called_functions)

    def get_calling_functions(self):
        return frozenset(self.calling_functions)

    def __str__(self):
        return super().__str__() + f" @ {self.get_entry_point().get_offset()}"
