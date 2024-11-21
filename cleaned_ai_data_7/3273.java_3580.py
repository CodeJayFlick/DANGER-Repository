class ProgramActionContext:
    def __init__(self, provider, program):
        self._program = program

    def __init__(self, provider, program, source_component=None):
        super().__init__(provider)
        if source_component is None:
            import tkinter as tk
            root = tk.Tk()
            set_source_object(root.focus_get())
        else:
            set_source_object(source_component)

    @property
    def program(self):
        return self._program

class ProgramActionContextProvider:
    pass  # not implemented in the original Java code, but needed for Python's super() call
