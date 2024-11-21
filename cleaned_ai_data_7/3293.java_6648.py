class ProgramSelectionPluginEvent:
    NAME = "ProgramSelection"

    def __init__(self, src, selection, program):
        self.selection = selection
        self.program_ref = weakref.ref(program)

    @property
    def selection(self):
        return self._selection

    @selection.setter
    def selection(self, value):
        if value is None:
            raise ValueError("ProgramSelection cannot be null")
        self._selection = value

    @property
    def program(self):
        return self.program_ref()

class PluginEvent:
    pass


def main():
    # Example usage of the ProgramSelectionPluginEvent class.
    selection_event = ProgramSelectionPluginEvent("src", "some_selection", some_program)
    print(selection_event.selection)  # prints: some_selection
    print(selection_event.program)   # prints: some_program

if __name__ == "__main__":
    main()
