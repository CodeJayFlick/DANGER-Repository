Here is the translation of the given Java code into Python:

```Python
class GhidraProgramTableModel:
    def __init__(self, model_name: str, program: object, task_monitor: object):
        self.program = program
        # Assuming that ThreadedTableModel and ProgramTableModel are not necessary in Python,
        # we can remove them as they seem to be specific to Java.
        pass

    def set_program(self, new_program: object) -> None:
        original_program = self.program
        self.program = new_program
        
        if original_program != new_program:
            self.clear_data()

    def clear_data(self):
        # This method is not implemented in the given code. It's assumed that it will be 
        # implemented based on the requirements.
        pass

    def get_program_for_row(self, row: object) -> object:
        return self.get_program()

    def get_program(self) -> object:
        return self.program

    def get_data_source(self) -> object:
        return self.get_program()
```

Note that Python does not have direct support for generics like Java. The `ROW_TYPE` parameter in the original code is equivalent to a generic type parameter in Python, but it's not explicitly defined here as we can't define custom types in this way in Python.